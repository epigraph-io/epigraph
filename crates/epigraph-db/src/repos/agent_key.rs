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
#[derive(Debug, Clone, sqlx::FromRow)]
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

/// How far before a key's `valid_from` a signed row may be dated and still be
/// admitted by [`key_window_admits`].
///
/// A row's `created_at` and a key's `valid_from` come from different clocks
/// (the writer's and the database's), so a writer a little behind the
/// database dates its first rows before the window opens. Clock skew, not a
/// security boundary; only the LOWER bound is relaxed, a window's END
/// (rotation, the legacy cut-over) stays exact.
pub const KEY_VALID_FROM_SKEW_SECS: i64 = 60;

/// Whether an attested key with this `status` and window admits a signature
/// on a row dated `at`: inside `[valid_from - KEY_VALID_FROM_SKEW_SECS,
/// valid_until)`, and ACTIVE, or ROTATED / EXPIRED with a recorded
/// `valid_until` (a rotated key with an open window records no end, so it
/// admits nothing). A REVOKED or PENDING key admits nothing: a revoked key is
/// treated as compromised from the start. `status` is in the SQL spelling
/// (`lower(btrim(..))`).
///
/// The ONE window rule: `epigraph-mcp`'s claim verifier and boot verdict and
/// the edge verifier (`repos::edge_signature`) all call it, so they cannot
/// disagree about a key.
#[must_use]
pub fn key_window_admits(
    status: &str,
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
    at: DateTime<Utc>,
) -> bool {
    let opens = valid_from - chrono::Duration::seconds(KEY_VALID_FROM_SKEW_SECS);
    if at < opens || valid_until.is_some_and(|until| at >= until) {
        return false;
    }
    match status {
        "active" => true,
        "rotated" | "expired" => valid_until.is_some(),
        _ => false,
    }
}

/// One ATTESTED key (`signing` or `identity-legacy`) of a claim's author or
/// signer, as [`AgentKeyRepository::attested_keys_for_claim`] returns it.
///
/// `key_type` and `status` are trimmed and lower-cased, the spelling migration
/// 161's guard compares, so a caller matches on exact literals.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AttestedKeyRow {
    /// The agent holding the key: the claim's author, its signer, or both.
    pub agent_id: Uuid,
    pub public_key: Vec<u8>,
    /// `"signing"` or `"identity-legacy"`.
    pub key_type: String,
    pub status: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
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

    /// Every `agent_keys` row carrying `public_key`, of any type and status,
    /// oldest first, with `key_type` and `status` trimmed and lower-cased in
    /// SQL (`lower(btrim(..))`): the spelling migration 161's guard and
    /// [`Self::attested_keys_for_claim`] compare, so a caller matches on exact
    /// literals and agrees with both. (Rust's `trim()` would also strip tabs
    /// and newlines, which `btrim` keeps, and so admit a row the guard does
    /// not treat as attested.)
    ///
    /// `epigraph-mcp`'s separate-signing-key boot check reads this, once at
    /// start-up on its own pool, to say precisely why a signing key does not
    /// admit (registered nowhere, to another agent, under another type, or no
    /// longer active). A pool, like this repository's other key reads, not a
    /// connection: it is not a request-path read, and `agent_keys` carries no
    /// tenancy to filter (no row security, and a public key is public).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn rows_with_public_key(
        pool: &PgPool,
        public_key: &[u8; 32],
    ) -> Result<Vec<AgentKeyRow>, DbError> {
        Ok(sqlx::query_as::<_, AgentKeyRow>(
            "SELECT id, agent_id, public_key, \
                    lower(btrim(key_type)) AS key_type, lower(btrim(status)) AS status, \
                    valid_from, valid_until, revocation_reason, revoked_by, created_at \
               FROM agent_keys WHERE public_key = $1 ORDER BY created_at, id",
        )
        .bind(public_key.as_slice())
        .fetch_all(pool)
        .await?)
    }

    /// The attested keys (`signing`, `identity-legacy`; any status) of a
    /// claim's AUTHOR (`claims.agent_id`) and of its SIGNER
    /// (`claims.signer_id`), for `verify_claim`'s key binding (agent identity
    /// lineage design D2). Empty when `viewer` cannot read the claim.
    ///
    /// Only the two attested types: migration 161's guard refuses a row of
    /// either to the application role, while any other type (`encryption`,
    /// `dual_purpose`) is application-insertable, so a key planted under one
    /// of those must never make a signature verify.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn attested_keys_for_claim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Vec<AttestedKeyRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT k.agent_id, k.public_key,
                   lower(btrim(k.key_type)) AS key_type,
                   lower(btrim(k.status)) AS status,
                   k.valid_from, k.valid_until
              FROM claims c
              JOIN agent_keys k ON k.agent_id = c.agent_id OR k.agent_id = c.signer_id
             WHERE c.id = $1
               AND lower(btrim(k.key_type)) IN ('signing', 'identity-legacy')
               /* {VISIBILITY:c} */
             ORDER BY k.created_at, k.id
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, AttestedKeyRow>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
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

    /// Get the agent's active key of one `key_type` (status = 'active').
    ///
    /// `idx_agent_keys_active` admits one active key per (agent, key_type),
    /// so an agent can hold several active keys of different types at once.
    /// Callers name the type they act on; rotation retires the active
    /// `'signing'` key and must never pick up a key of another type.
    ///
    /// Rotation passes `'signing'`: since migration 161 every agent also has an
    /// active `identity-legacy` key, whose private half is often computable
    /// from public inputs, so it must never be the key a rotation acts on.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_active_key(
        pool: &PgPool,
        agent_id: AgentId,
        key_type: &str,
    ) -> Result<Option<AgentKeyRow>, DbError> {
        let agent_uuid: Uuid = agent_id.as_uuid();

        let row = sqlx::query_as::<_, AgentKeyRow>(
            "SELECT id, agent_id, public_key, key_type, status, valid_from, valid_until, \
                    revocation_reason, revoked_by, created_at \
               FROM agent_keys \
              WHERE agent_id = $1 AND key_type = $2 AND status = 'active' \
              ORDER BY created_at DESC \
              LIMIT 1",
        )
        .bind(agent_uuid)
        .bind(key_type)
        .fetch_optional(pool)
        .await?;

        Ok(row)
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
        // Migration 118: `epigraph_agent_key_set_status` is a SECURITY DEFINER
        // that admits only active -> rotated and (not revoked) -> revoked, and
        // changes no column but status / revocation_reason / revoked_by. The
        // application role holds no UPDATE on `agent_keys`.
        let row = sqlx::query_as::<_, AgentKeyRow>(
            "SELECT id, agent_id, public_key, key_type, status, valid_from, valid_until, \
                    revocation_reason, revoked_by, created_at \
             FROM public.epigraph_agent_key_set_status($1, $2, $3, $4)",
        )
        .bind(key_id)
        .bind(status)
        .bind(revocation_reason)
        .bind(revoked_by)
        .fetch_optional(pool)
        .await?;

        row.ok_or_else(|| DbError::NotFound {
            entity: "AgentKey".to_string(),
            id: key_id,
        })
    }

    /// Full update of a key row.
    ///
    /// A direct UPDATE of every mutable column. Since migration 118 the
    /// application role holds no UPDATE on `agent_keys`, so this runs only on a
    /// privileged connection; the request path uses [`Self::update_status`].
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
