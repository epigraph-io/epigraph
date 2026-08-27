//! Agent repository for database operations

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use epigraph_core::{Agent, AgentId};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// A database row combining agent identity fields with capability flags.
///
/// Uses primitive types (no `epigraph-api` imports) so callers can convert
/// to their own domain types without a circular dependency.
#[derive(Debug, Clone)]
pub struct AgentIdentityRow {
    pub id: Uuid,
    pub public_key: Vec<u8>,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub labels: Vec<String>,
    pub orcid: Option<String>,
    pub ror_id: Option<String>,
    /// e.g. "researcher", "orchestrator", "tool_agent", "custom"
    pub role: String,
    /// e.g. "active", "suspended", "banned"
    pub state: String,
    /// Optional JSON blob describing the reason for the current state
    pub state_reason: Option<JsonValue>,
    pub parent_agent_id: Option<Uuid>,
    pub metadata: JsonValue,
    pub rate_limit_rpm: i32,
    pub concurrency_limit: i32,
    // Capability fields (NULL when no row in agent_capabilities yet)
    pub can_submit_claims: Option<bool>,
    pub can_provide_evidence: Option<bool>,
    pub can_challenge_claims: Option<bool>,
    pub can_invoke_tools: Option<bool>,
    pub can_spawn_agents: Option<bool>,
    pub can_modify_policies: Option<bool>,
    pub privileged_access: Option<bool>,
}

/// A writeable capabilities row.  Pass this to `update_capabilities`.
#[derive(Debug, Clone)]
pub struct AgentCapabilitiesRow {
    pub can_submit_claims: bool,
    pub can_provide_evidence: bool,
    pub can_challenge_claims: bool,
    pub can_invoke_tools: bool,
    pub can_spawn_agents: bool,
    pub can_modify_policies: bool,
    pub privileged_access: bool,
}

/// Filter for `find_by_capability`.  Each field is `Some(true)` to require
/// the capability, `Some(false)` to require its absence, or `None` to ignore.
#[derive(Debug, Clone, Default)]
pub struct CapabilityFilter {
    pub can_submit_claims: Option<bool>,
    pub can_provide_evidence: Option<bool>,
    pub can_challenge_claims: Option<bool>,
    pub can_invoke_tools: Option<bool>,
    pub can_spawn_agents: Option<bool>,
    pub can_modify_policies: Option<bool>,
    pub privileged_access: Option<bool>,
}

/// Repository for Agent operations
pub struct AgentRepository;

impl AgentRepository {
    /// Create a new agent in the database
    ///
    /// # Errors
    /// Returns `DbError::DuplicateKey` if an agent with the same public key already exists.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[instrument(skip(pool, agent))]
    pub async fn create(pool: &PgPool, agent: &Agent) -> Result<Agent, DbError> {
        let id: Uuid = agent.id.into();
        let public_key = &agent.public_key;
        let display_name = agent.display_name.as_deref();
        let created_at = agent.created_at;

        let row = sqlx::query!(
            r#"
            INSERT INTO agents (id, public_key, display_name, created_at, updated_at, labels, orcid, ror_id)
            VALUES ($1, $2, $3, $4, $4, $5, $6, $7)
            RETURNING id, public_key, display_name, created_at, labels, orcid, ror_id
            "#,
            id,
            public_key.as_slice(),
            display_name,
            created_at,
            &agent.labels as &[String],
            agent.orcid.as_deref(),
            agent.ror_id.as_deref(),
        )
        .fetch_one(pool)
        .await
        .map_err(|err| {
            if let sqlx::Error::Database(ref db_err) = err {
                if db_err.is_unique_violation() {
                    return DbError::DuplicateKey {
                        entity: "Agent".to_string(),
                    };
                }
            }
            DbError::from(err)
        })?;

        // Convert BYTEA to [u8; 32]
        let public_key: [u8; 32] = row
            .public_key
            .try_into()
            .map_err(|_| DbError::InvalidData {
                reason: "public_key is not 32 bytes".to_string(),
            })?;

        // Fire-and-forget agent.registered event (closes #61).
        // The downstream write has already committed (we hold `row`); the
        // event log is a separate observability surface and must not roll
        // back the agent on failure.
        let _ = crate::repos::EventRepository::publish_or_log(
            pool,
            "agent.registered",
            Some(row.id),
            &serde_json::json!({
                "agent_id": row.id,
                "display_name": row.display_name,
                "public_key": public_key.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            }),
        )
        .await;

        Ok(Agent::with_id(
            AgentId::from_uuid(row.id),
            public_key,
            row.display_name,
            row.created_at,
            row.labels,
            row.orcid,
            row.ror_id,
        ))
    }

    /// Find an agent by public key, else create it. Idempotent on `public_key`.
    ///
    /// Returns the resolved agent and `true` if it was freshly created, `false`
    /// if an existing row was found. Assumes the only realistic unique collision
    /// is `agents_public_key_unique` (the `id` is a fresh UUID). Narrow this
    /// match if a future migration adds another unique constraint on `agents`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if a lookup or insert fails for reasons
    /// other than the public-key uniqueness race, and `DbError::InvalidData`
    /// if a raced-in row cannot be re-found after a `DuplicateKey`.
    #[instrument(skip(pool, agent))]
    pub async fn create_or_get(pool: &PgPool, agent: &Agent) -> Result<(Agent, bool), DbError> {
        if let Some(existing) = Self::get_by_public_key(pool, &agent.public_key).await? {
            return Ok((existing, false));
        }
        match Self::create(pool, agent).await {
            Ok(created) => Ok((created, true)),
            Err(DbError::DuplicateKey { .. }) => {
                // Lost a concurrent registration race — re-find.
                match Self::get_by_public_key(pool, &agent.public_key).await? {
                    Some(existing) => Ok((existing, false)),
                    None => Err(DbError::InvalidData {
                        reason: "agent disappeared after DuplicateKey".to_string(),
                    }),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Get an agent by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: AgentId) -> Result<Option<Agent>, DbError> {
        let uuid: Uuid = id.into();

        let row = sqlx::query!(
            r#"
            SELECT id, public_key, display_name, created_at, labels, orcid, ror_id
            FROM agents
            WHERE id = $1
            "#,
            uuid
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => {
                let public_key: [u8; 32] =
                    row.public_key
                        .try_into()
                        .map_err(|_| DbError::InvalidData {
                            reason: "public_key is not 32 bytes".to_string(),
                        })?;

                Ok(Some(Agent::with_id(
                    AgentId::from_uuid(row.id),
                    public_key,
                    row.display_name,
                    row.created_at,
                    row.labels,
                    row.orcid,
                    row.ror_id,
                )))
            }
            None => Ok(None),
        }
    }

    /// Get an agent by their public key
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, public_key))]
    pub async fn get_by_public_key(
        pool: &PgPool,
        public_key: &[u8; 32],
    ) -> Result<Option<Agent>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT id, public_key, display_name, created_at, labels, orcid, ror_id
            FROM agents
            WHERE public_key = $1
            "#,
            public_key.as_slice()
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => {
                let public_key: [u8; 32] =
                    row.public_key
                        .try_into()
                        .map_err(|_| DbError::InvalidData {
                            reason: "public_key is not 32 bytes".to_string(),
                        })?;

                Ok(Some(Agent::with_id(
                    AgentId::from_uuid(row.id),
                    public_key,
                    row.display_name,
                    row.created_at,
                    row.labels,
                    row.orcid,
                    row.ror_id,
                )))
            }
            None => Ok(None),
        }
    }

    /// Get an agent by ORCID identifier
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_orcid(pool: &PgPool, orcid: &str) -> Result<Option<Agent>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT id, public_key, display_name, created_at, labels, orcid, ror_id
            FROM agents
            WHERE orcid = $1
            "#,
            orcid
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => {
                let public_key: [u8; 32] =
                    row.public_key
                        .try_into()
                        .map_err(|_| DbError::InvalidData {
                            reason: "public_key is not 32 bytes".to_string(),
                        })?;

                Ok(Some(Agent::with_id(
                    AgentId::from_uuid(row.id),
                    public_key,
                    row.display_name,
                    row.created_at,
                    row.labels,
                    row.orcid,
                    row.ror_id,
                )))
            }
            None => Ok(None),
        }
    }

    /// Get an agent by ROR identifier
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_ror_id(pool: &PgPool, ror_id: &str) -> Result<Option<Agent>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT id, public_key, display_name, created_at, labels, orcid, ror_id
            FROM agents
            WHERE ror_id = $1
            "#,
            ror_id
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => {
                let public_key: [u8; 32] =
                    row.public_key
                        .try_into()
                        .map_err(|_| DbError::InvalidData {
                            reason: "public_key is not 32 bytes".to_string(),
                        })?;

                Ok(Some(Agent::with_id(
                    AgentId::from_uuid(row.id),
                    public_key,
                    row.display_name,
                    row.created_at,
                    row.labels,
                    row.orcid,
                    row.ror_id,
                )))
            }
            None => Ok(None),
        }
    }

    /// Update an agent's display name, labels, orcid, and ror_id
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if the agent doesn't exist.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[instrument(skip(pool, agent))]
    pub async fn update(pool: &PgPool, agent: &Agent) -> Result<Agent, DbError> {
        let id: Uuid = agent.id.into();
        let display_name = agent.display_name.as_deref();

        let row = sqlx::query!(
            r#"
            UPDATE agents
            SET display_name = $2, labels = $3, orcid = $4, ror_id = $5, updated_at = NOW()
            WHERE id = $1
            RETURNING id, public_key, display_name, created_at, labels, orcid, ror_id
            "#,
            id,
            display_name,
            &agent.labels as &[String],
            agent.orcid.as_deref(),
            agent.ror_id.as_deref(),
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => {
                let public_key: [u8; 32] =
                    row.public_key
                        .try_into()
                        .map_err(|_| DbError::InvalidData {
                            reason: "public_key is not 32 bytes".to_string(),
                        })?;

                Ok(Agent::with_id(
                    AgentId::from_uuid(row.id),
                    public_key,
                    row.display_name,
                    row.created_at,
                    row.labels,
                    row.orcid,
                    row.ror_id,
                ))
            }
            None => Err(DbError::NotFound {
                entity: "Agent".to_string(),
                id,
            }),
        }
    }

    /// Delete an agent by ID
    ///
    /// Detaches any `events.actor_id` references first (sets them to NULL)
    /// so the audit log outlives the deleted agent. Without this step the
    /// `events_actor_id_fkey` FK would block agent deletion any time the
    /// agent had logged a `tool.invoked`, `agent.registered`, or
    /// `claim.created` event — see #61 wiring.
    ///
    /// # Returns
    /// Returns `true` if the agent was deleted, `false` if it didn't exist.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn delete(pool: &PgPool, id: AgentId) -> Result<bool, DbError> {
        let uuid: Uuid = id.into();

        let mut tx = pool.begin().await?;

        // Audit log outlives the agent: NULL out `actor_id` references
        // before deleting, otherwise the FK fires.
        sqlx::query!(
            "UPDATE events SET actor_id = NULL WHERE actor_id = $1",
            uuid
        )
        .execute(&mut *tx)
        .await?;

        let result = sqlx::query!(
            r#"
            DELETE FROM agents
            WHERE id = $1
            "#,
            uuid
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(result.rows_affected() > 0)
    }

    /// List agents with pagination
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `limit` - Maximum number of agents to return
    /// * `offset` - Number of agents to skip
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<Agent>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, public_key, display_name, created_at, labels, orcid, ror_id
            FROM agents
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
            limit,
            offset
        )
        .fetch_all(pool)
        .await?;

        let mut agents = Vec::with_capacity(rows.len());

        for row in rows {
            let public_key: [u8; 32] =
                row.public_key
                    .try_into()
                    .map_err(|_| DbError::InvalidData {
                        reason: "public_key is not 32 bytes".to_string(),
                    })?;

            agents.push(Agent::with_id(
                AgentId::from_uuid(row.id),
                public_key,
                row.display_name,
                row.created_at,
                row.labels,
                row.orcid,
                row.ror_id,
            ));
        }

        Ok(agents)
    }

    /// List agents filtered by label with pagination
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_by_label(
        pool: &PgPool,
        label: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Agent>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, public_key, display_name, created_at, labels, orcid, ror_id
            FROM agents
            WHERE $1 = ANY(labels)
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
            label,
            limit,
            offset
        )
        .fetch_all(pool)
        .await?;

        let mut agents = Vec::with_capacity(rows.len());
        for row in rows {
            let public_key: [u8; 32] =
                row.public_key
                    .try_into()
                    .map_err(|_| DbError::InvalidData {
                        reason: "public_key is not 32 bytes".to_string(),
                    })?;

            agents.push(Agent::with_id(
                AgentId::from_uuid(row.id),
                public_key,
                row.display_name,
                row.created_at,
                row.labels,
                row.orcid,
                row.ror_id,
            ));
        }

        Ok(agents)
    }

    /// Count total number of agents
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn count(pool: &PgPool) -> Result<i64, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM agents
            "#
        )
        .fetch_one(pool)
        .await?;

        Ok(row.count.unwrap_or(0))
    }

    /// Count agents with a specific label
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn count_by_label(pool: &PgPool, label: &str) -> Result<i64, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM agents
            WHERE $1 = ANY(labels)
            "#,
            label
        )
        .fetch_one(pool)
        .await?;

        Ok(row.count.unwrap_or(0))
    }

    // ─── Identity / capability queries ───────────────────────────────────────

    /// Fetch an agent together with its role, state, and capability flags in a
    /// single JOIN query.
    ///
    /// Returns `None` when no agent with the given ID exists.
    ///
    /// Uses a runtime query (not `sqlx::query!`) because the LEFT JOIN makes
    /// capability columns nullable in a way that requires live DB introspection
    /// for the compile-time macro, which is unavailable under SQLX_OFFLINE=true.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_with_identity(
        pool: &PgPool,
        id: AgentId,
    ) -> Result<Option<AgentIdentityRow>, DbError> {
        use sqlx::Row as _;

        let uuid: Uuid = id.into();

        let row = sqlx::query(
            r#"
            SELECT
                a.id,
                a.public_key,
                a.display_name,
                a.created_at,
                a.labels,
                a.orcid,
                a.ror_id,
                a.role,
                a.state,
                a.state_reason,
                a.parent_agent_id,
                a.metadata,
                a.rate_limit_rpm,
                a.concurrency_limit,
                ac.can_submit_claims,
                ac.can_provide_evidence,
                ac.can_challenge_claims,
                ac.can_invoke_tools,
                ac.can_spawn_agents,
                ac.can_modify_policies,
                ac.privileged_access
            FROM agents a
            LEFT JOIN agent_capabilities ac ON ac.agent_id = a.id
            WHERE a.id = $1
            "#,
        )
        .bind(uuid)
        .fetch_optional(pool)
        .await?;

        match row {
            None => Ok(None),
            Some(r) => Ok(Some(AgentIdentityRow {
                id: r.try_get("id")?,
                public_key: r.try_get("public_key")?,
                display_name: r.try_get("display_name")?,
                created_at: r.try_get("created_at")?,
                labels: r.try_get("labels")?,
                orcid: r.try_get("orcid")?,
                ror_id: r.try_get("ror_id")?,
                role: r.try_get("role")?,
                state: r.try_get("state")?,
                state_reason: r.try_get("state_reason")?,
                parent_agent_id: r.try_get("parent_agent_id")?,
                metadata: r.try_get("metadata")?,
                rate_limit_rpm: r.try_get("rate_limit_rpm")?,
                concurrency_limit: r.try_get("concurrency_limit")?,
                can_submit_claims: r.try_get("can_submit_claims")?,
                can_provide_evidence: r.try_get("can_provide_evidence")?,
                can_challenge_claims: r.try_get("can_challenge_claims")?,
                can_invoke_tools: r.try_get("can_invoke_tools")?,
                can_spawn_agents: r.try_get("can_spawn_agents")?,
                can_modify_policies: r.try_get("can_modify_policies")?,
                privileged_access: r.try_get("privileged_access")?,
            })),
        }
    }

    /// Update the role column for an agent.
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if no agent with the given ID exists.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[instrument(skip(pool))]
    pub async fn update_role(pool: &PgPool, id: AgentId, role: &str) -> Result<(), DbError> {
        let uuid: Uuid = id.into();

        let result = sqlx::query(
            r#"
            UPDATE agents
            SET role = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(uuid)
        .bind(role)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "Agent".to_string(),
                id: uuid,
            });
        }

        Ok(())
    }

    /// Atomically transition an agent's state.
    ///
    /// The method:
    /// 1. Reads the current state inside a transaction.
    /// 2. Inserts a row into `agent_state_history` recording the transition.
    /// 3. Updates `agents.state` and `agents.state_reason`.
    ///
    /// # Arguments
    /// * `id` — the agent being transitioned
    /// * `new_state` — target state string (e.g. `"suspended"`)
    /// * `reason_json` — optional JSON blob describing the reason
    /// * `changed_by` — the agent (or operator) that initiated the change
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if no agent with the given ID exists.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[instrument(skip(pool, reason_json))]
    pub async fn update_state(
        pool: &PgPool,
        id: AgentId,
        new_state: &str,
        reason_json: Option<JsonValue>,
        changed_by: Option<AgentId>,
    ) -> Result<(), DbError> {
        use sqlx::Row as _;

        let uuid: Uuid = id.into();
        let changed_by_uuid: Option<Uuid> = changed_by.map(Into::into);

        let mut tx = pool.begin().await?;

        // 1. Fetch the current state (also validates the agent exists).
        let current = sqlx::query(r#"SELECT state FROM agents WHERE id = $1 FOR UPDATE"#)
            .bind(uuid)
            .fetch_optional(&mut *tx)
            .await?;

        let current_state: String = match current {
            Some(row) => row.try_get("state")?,
            None => {
                tx.rollback().await.ok();
                return Err(DbError::NotFound {
                    entity: "Agent".to_string(),
                    id: uuid,
                });
            }
        };

        // 2. Record the transition.
        sqlx::query(
            r#"
            INSERT INTO agent_state_history
                (agent_id, previous_state, new_state, reason, changed_by)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(uuid)
        .bind(&current_state)
        .bind(new_state)
        .bind(&reason_json)
        .bind(changed_by_uuid)
        .execute(&mut *tx)
        .await?;

        // 3. Apply the new state.
        sqlx::query(
            r#"
            UPDATE agents
            SET state = $2, state_reason = $3, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(uuid)
        .bind(new_state)
        .bind(&reason_json)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Upsert the capability flags for an agent.
    ///
    /// Inserts a new row or updates all capability columns if one already
    /// exists (`ON CONFLICT … DO UPDATE`).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, capabilities))]
    pub async fn update_capabilities(
        pool: &PgPool,
        agent_id: AgentId,
        capabilities: &AgentCapabilitiesRow,
    ) -> Result<(), DbError> {
        let uuid: Uuid = agent_id.into();

        sqlx::query(
            r#"
            INSERT INTO agent_capabilities (
                agent_id,
                can_submit_claims,
                can_provide_evidence,
                can_challenge_claims,
                can_invoke_tools,
                can_spawn_agents,
                can_modify_policies,
                privileged_access
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (agent_id) DO UPDATE
            SET can_submit_claims    = EXCLUDED.can_submit_claims,
                can_provide_evidence = EXCLUDED.can_provide_evidence,
                can_challenge_claims = EXCLUDED.can_challenge_claims,
                can_invoke_tools     = EXCLUDED.can_invoke_tools,
                can_spawn_agents     = EXCLUDED.can_spawn_agents,
                can_modify_policies  = EXCLUDED.can_modify_policies,
                privileged_access    = EXCLUDED.privileged_access,
                updated_at           = NOW()
            "#,
        )
        .bind(uuid)
        .bind(capabilities.can_submit_claims)
        .bind(capabilities.can_provide_evidence)
        .bind(capabilities.can_challenge_claims)
        .bind(capabilities.can_invoke_tools)
        .bind(capabilities.can_spawn_agents)
        .bind(capabilities.can_modify_policies)
        .bind(capabilities.privileged_access)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Merge LLM-identity provenance into an agent's `properties` JSONB.
    ///
    /// Sets `llm_model`, `llm_prompt_hash`, and `source = "mcp-llm-agent"`.
    /// The `properties || $2::jsonb` concatenation MERGES the object: keys
    /// already present in `properties` but absent from the patch survive; only
    /// the three keys here are added/overwritten. This never clobbers the full
    /// blob (unlike `SET properties = $2`).
    ///
    /// Deliberately separate from `create()` per the repo blast-radius rule:
    /// `create()` has many callers and must not learn about LLM identity.
    ///
    /// Idempotent: re-running with the same values yields the same properties.
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if no agent with the given ID exists.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[instrument(skip(pool))]
    pub async fn set_llm_properties(
        pool: &PgPool,
        agent_id: Uuid,
        model: &str,
        prompt_hash: &str,
    ) -> Result<(), DbError> {
        let patch = serde_json::json!({
            "llm_model": model,
            "llm_prompt_hash": prompt_hash,
            "source": "mcp-llm-agent",
        });

        let result = sqlx::query!(
            r#"
            UPDATE agents
            SET properties = properties || $2::jsonb, updated_at = NOW()
            WHERE id = $1
            "#,
            agent_id,
            patch,
        )
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "Agent".to_string(),
                id: agent_id,
            });
        }

        Ok(())
    }

    /// Return all agents with a given role value.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn find_by_role(pool: &PgPool, role: &str) -> Result<Vec<Agent>, DbError> {
        use sqlx::Row as _;

        let rows = sqlx::query(
            r#"
            SELECT id, public_key, display_name, created_at, labels, orcid, ror_id
            FROM agents
            WHERE role = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(role)
        .fetch_all(pool)
        .await?;

        let mut agents = Vec::with_capacity(rows.len());
        for row in rows {
            let public_key_bytes: Vec<u8> = row.try_get("public_key")?;
            let public_key: [u8; 32] =
                public_key_bytes
                    .try_into()
                    .map_err(|_| DbError::InvalidData {
                        reason: "public_key is not 32 bytes".to_string(),
                    })?;

            agents.push(Agent::with_id(
                AgentId::from_uuid(row.try_get("id")?),
                public_key,
                row.try_get("display_name")?,
                row.try_get("created_at")?,
                row.try_get("labels")?,
                row.try_get("orcid")?,
                row.try_get("ror_id")?,
            ));
        }
        Ok(agents)
    }

    /// Return all agents whose `agent_capabilities` row satisfies every
    /// constraint expressed in `filter`.
    ///
    /// Fields set to `None` are ignored (any value is accepted).
    /// Fields set to `Some(true)` require the capability to be `true`.
    /// Fields set to `Some(false)` require the capability to be `false`.
    ///
    /// Agents that have no row in `agent_capabilities` are excluded when any
    /// filter field is `Some(…)`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, filter))]
    pub async fn find_by_capability(
        pool: &PgPool,
        filter: &CapabilityFilter,
    ) -> Result<Vec<Agent>, DbError> {
        use sqlx::Row as _;

        // Build the WHERE clause dynamically.  Positional parameters ($1…$N)
        // are appended for each Some(v) in the filter.
        let mut sql = String::from(
            r#"
            SELECT a.id, a.public_key, a.display_name, a.created_at, a.labels, a.orcid, a.ror_id
            FROM agents a
            INNER JOIN agent_capabilities ac ON ac.agent_id = a.id
            WHERE 1=1
            "#,
        );

        let mut param_idx: u32 = 1;
        let mut bool_params: Vec<bool> = Vec::new();

        macro_rules! add_filter {
            ($field:expr, $col:expr) => {
                if let Some(v) = $field {
                    sql.push_str(&format!(" AND ac.{} = ${}", $col, param_idx));
                    bool_params.push(v);
                    param_idx += 1;
                }
            };
        }

        add_filter!(filter.can_submit_claims, "can_submit_claims");
        add_filter!(filter.can_provide_evidence, "can_provide_evidence");
        add_filter!(filter.can_challenge_claims, "can_challenge_claims");
        add_filter!(filter.can_invoke_tools, "can_invoke_tools");
        add_filter!(filter.can_spawn_agents, "can_spawn_agents");
        add_filter!(filter.can_modify_policies, "can_modify_policies");
        add_filter!(filter.privileged_access, "privileged_access");

        // Suppress the "value assigned but never read" warning on the last
        // increment of param_idx.
        let _ = param_idx;

        sql.push_str(" ORDER BY a.created_at DESC");

        // Bind each bool parameter in order using the chained `.bind()` API.
        let mut query = sqlx::query(&sql);
        for v in &bool_params {
            query = query.bind(*v);
        }

        let rows = query.fetch_all(pool).await?;

        let mut agents = Vec::with_capacity(rows.len());
        for row in rows {
            let public_key_bytes: Vec<u8> = row.try_get("public_key")?;
            let public_key: [u8; 32] =
                public_key_bytes
                    .try_into()
                    .map_err(|_| DbError::InvalidData {
                        reason: "public_key is not 32 bytes".to_string(),
                    })?;

            agents.push(Agent::with_id(
                AgentId::from_uuid(row.try_get("id")?),
                public_key,
                row.try_get("display_name")?,
                row.try_get("created_at")?,
                row.try_get("labels")?,
                row.try_get("orcid")?,
                row.try_get("ror_id")?,
            ));
        }
        Ok(agents)
    }

    // =========================================================================
    // OAuth principal identity (PR-02)
    //
    // Every one of the queries below uses the RUNTIME `sqlx::query`/`query_as`
    // API rather than the `query!` macros. That is deliberate: they read and
    // write `agents.key_kind`, which only exists once migration 061 has been
    // applied, and a macro would demand a `.sqlx/` cache entry describing a
    // column that a not-yet-migrated checkout cannot produce.
    // =========================================================================

    /// Idempotently materialise the `agents` row for an OAuth client, so
    /// `AuthContext.agent_id` is never `None` on an authenticated request.
    ///
    /// This IS the "linked later" helper that
    /// `crates/epigraph-api/src/oauth/register.rs` promised in a comment, named,
    /// and never had. It is called at every token-mint site rather than at
    /// registration time, so a client registered before this shipped acquires
    /// its principal on its next token.
    ///
    /// Steps, all on the caller's connection so the caller may wrap them in one
    /// transaction:
    /// 1. `SELECT agent_id, client_id, client_type FROM oauth_clients ...
    ///    FOR UPDATE` — early return when the client is already linked (the warm
    ///    path: one indexed read). `client_type` is read from the LOCKED ROW
    ///    rather than taken as a parameter, so a caller cannot pass one
    ///    inconsistent with what is stored (`providers::provision` hardcoded
    ///    `"human"`).
    /// 2. **`client_type = 'agent'` first.** For an agent client the `client_id`
    ///    IS the hex Ed25519 public key by construction
    ///    (`oauth/register.rs` requires it; `oauth/token.rs` decodes it to
    ///    verify the client assertion). Such a client already HAS a signing
    ///    identity, and elsewhere the kernel resolves that identity by
    ///    `agents.public_key` (`routes/policies.rs`, `routes/workflows.rs`). If
    ///    a derived placeholder were minted instead, the token's `agent_id`
    ///    would name a different row than the agent's own claims are authored
    ///    under — so under PR-03/PR-07, where the JWT principal becomes the
    ///    viewer identity, an agent's own claims would be invisible to its own
    ///    token. So: if `client_id` decodes to 32 bytes and an `ed25519` agent
    ///    holds that key, link to THAT row.
    /// 3. Otherwise derive a 32-byte PLACEHOLDER public key from the client's
    ///    row id. `agents.public_key` is `bytea NOT NULL CHECK (octet_length =
    ///    32)` with a UNIQUE constraint, so a keyless principal cannot exist
    ///    without one. It is recorded as `key_kind = 'derived'`; it is **not** a
    ///    signature verifier and every signature path must filter
    ///    `key_kind = 'ed25519'` (see [`Self::public_key_if_signer`]).
    /// 4. insert the agent,
    ///    `ON CONFLICT (public_key) DO UPDATE ... WHERE agents.key_kind =
    ///    'derived' RETURNING`. `DO UPDATE` rather than `DO NOTHING` is
    ///    load-bearing: `DO NOTHING` returns no row on the lost-race path, which
    ///    would surface as intermittent 500s under concurrent first-mints. The
    ///    `WHERE agents.key_kind = 'derived'` is a SECURITY predicate: without
    ///    it, an unconditional `DO UPDATE` ADOPTS whatever row already holds
    ///    that key, `key_kind = 'ed25519'` included, and the invariant
    ///    [`Self::public_key_if_signer`] rests on — "an OAuth-principal agent is
    ///    never a signer" — silently fails. It is reachable:
    ///    `POST /api/v1/agents` accepts an arbitrary 32-byte `public_key` from
    ///    any `agents:write` holder, and `oauth_clients.id` is exposed as the
    ///    JWT `sub` and by the admin client listing, so pre-creating an agent at
    ///    `blake3::derive_key("epigraph-oauth-client", <victim client uuid>)`
    ///    with a key you hold the private half of would make you that client's
    ///    principal, with a real verifier. Zero returned rows is therefore a
    ///    hard error, not a retry.
    /// 5. link the client (write-once; see
    ///    `OAuthClientRepository::set_agent_id`).
    /// 6. ensure the principal's personal group exists.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any statement fails,
    /// `DbError::InvalidData` if `client_row_id` names no `oauth_clients` row,
    /// and `DbError::DuplicateKey` if the derived key is squatted by a row that
    /// is not a `derived` OAuth principal.
    #[instrument(skip(conn))]
    pub async fn ensure_for_client(
        conn: &mut sqlx::PgConnection,
        client_row_id: Uuid,
    ) -> Result<AgentId, DbError> {
        // 1. Lock the client row and check for an existing link.
        let existing: Option<(Option<Uuid>, String, String)> = sqlx::query_as(
            "SELECT agent_id, client_id, client_type FROM oauth_clients WHERE id = $1 FOR UPDATE",
        )
        .bind(client_row_id)
        .fetch_optional(&mut *conn)
        .await?;

        let (client_id, client_type) = match existing {
            Some((Some(agent_id), _, _)) => return Ok(AgentId::from_uuid(agent_id)),
            Some((None, client_id, client_type)) => (client_id, client_type),
            None => {
                return Err(DbError::InvalidData {
                    reason: format!("oauth_clients row {client_row_id} does not exist"),
                })
            }
        };

        // `agents.agent_type` has no CHECK, but the kernel's vocabulary is
        // human | software_agent. Map the OAuth client_type onto it.
        let agent_type = match client_type.as_str() {
            "human" => "human",
            _ => "software_agent", // "agent" and "service"
        };
        let display_name = format!("oauth:{client_row_id}");

        // 2. An agent client's client_id IS its Ed25519 public key. Adopt the
        //    real signer row when one exists rather than minting a second,
        //    derived principal beside it.
        let real_signer: Option<Uuid> = if client_type == "agent" {
            match hex::decode(&client_id) {
                Ok(bytes) if bytes.len() == 32 => {
                    let row: Option<(Uuid,)> = sqlx::query_as(
                        "SELECT id FROM agents WHERE public_key = $1 AND key_kind = 'ed25519'",
                    )
                    .bind(bytes.as_slice())
                    .fetch_optional(&mut *conn)
                    .await?;
                    row.map(|r| r.0)
                }
                _ => None,
            }
        } else {
            None
        };

        let agent_id = if let Some(id) = real_signer {
            id
        } else {
            // 3. Derive the placeholder key.
            let derived = blake3::derive_key("epigraph-oauth-client", client_row_id.as_bytes());

            // 4. Insert (or re-find) the agent — but ONLY ever a derived one.
            let row: Option<(Uuid,)> = sqlx::query_as(
                r#"
                INSERT INTO agents (public_key, display_name, agent_type, key_kind, labels)
                VALUES ($1, $2, $3, 'derived', ARRAY['oauth-principal'])
                ON CONFLICT (public_key) DO UPDATE SET updated_at = now()
                    WHERE agents.key_kind = 'derived'
                RETURNING id
                "#,
            )
            .bind(derived.as_slice())
            .bind(&display_name)
            .bind(agent_type)
            .fetch_optional(&mut *conn)
            .await?;

            row.ok_or_else(|| DbError::DuplicateKey {
                entity: format!(
                    "agents.public_key derived for oauth_clients {client_row_id} is held by a \
                     non-derived agent; refusing to adopt it as an OAuth principal"
                ),
            })?
            .0
        };

        // 5. Link the client (write-once).
        crate::repos::oauth_client::OAuthClientRepository::set_agent_id(
            &mut *conn,
            client_row_id,
            agent_id,
        )
        .await?;

        // 6. Personal group, so D2's derivation is total from the first token.
        Self::ensure_personal_group(&mut *conn, agent_id).await?;

        Ok(AgentId::from_uuid(agent_id))
    }

    /// Idempotently create the agent's personal group and its own live
    /// `role='admin'` membership in it. Returns the group id.
    ///
    /// Idempotency comes from a deterministic `did_key`
    /// (`did:epigraph:personal:<agent_uuid>`) against the existing
    /// `groups_did_key_key UNIQUE`, so no extra column on `agents` is needed to
    /// remember it.
    ///
    /// `public_key = ''::bytea` is mandatory, not a shortcut:
    /// `groups_public_key_shape` (migration 060) requires
    /// `octet_length(public_key) = 0` for every `kind <> 'team'`. A personal
    /// group carries no key material at all, so no `group_key_epochs` row is
    /// created either — `group_memberships` has no FK to it, and the
    /// membership's `wrapped_key_share` is empty for the same reason.
    ///
    /// The membership insert targets the composite
    /// `(group_id, agent_id, epoch)` UNIQUE and **revives** on conflict. An
    /// untargeted `ON CONFLICT DO NOTHING` was wrong: if the epoch-0 row exists
    /// with `revoked_at` set, the partial index `group_memberships_one_live`
    /// does not conflict but the composite UNIQUE does, so the insert silently
    /// no-ops and the agent has NO live membership in its own personal group —
    /// permanently, since every later mint hits the same conflict. Targeting the
    /// composite is safe here precisely because a personal group has exactly one
    /// member at exactly one epoch, so no OTHER live row can exist for the
    /// partial index to trip over.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if either statement fails.
    #[instrument(skip(conn))]
    pub async fn ensure_personal_group(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
    ) -> Result<Uuid, DbError> {
        let (group_id,): (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id)
            VALUES ($2, 'did:epigraph:personal:' || $1::text, ''::bytea, 'personal', $1)
            ON CONFLICT (did_key) DO UPDATE SET updated_at = now()
            RETURNING id
            "#,
        )
        .bind(agent_id)
        .bind(format!("personal:{agent_id}"))
        .fetch_one(&mut *conn)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role)
            VALUES ($1, $2, ''::bytea, 0, 'admin')
            ON CONFLICT (group_id, agent_id, epoch)
            DO UPDATE SET revoked_at = NULL, role = 'admin'
            "#,
        )
        .bind(group_id)
        .bind(agent_id)
        .execute(&mut *conn)
        .await?;

        Ok(group_id)
    }

    /// The agent's public key, but **only** when it is a real Ed25519 verifier.
    ///
    /// Returns `None` both for an unknown agent and for one whose `public_key`
    /// is the `key_kind = 'derived'` placeholder written by
    /// [`Self::ensure_for_client`]. A derived key is a BLAKE3 output — nobody
    /// knows a private key for it, so feeding it to an Ed25519 verifier would
    /// merely fail; but it is indistinguishable from a real key to any reader
    /// that does not filter, so signature paths call THIS, never a bare
    /// `SELECT public_key FROM agents`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn public_key_if_signer(
        conn: &mut sqlx::PgConnection,
        id: Uuid,
    ) -> Result<Option<Vec<u8>>, DbError> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT public_key FROM agents WHERE id = $1 AND key_kind = 'ed25519'")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await?;
        Ok(row.map(|r| r.0))
    }
}

#[cfg(test)]
mod tests {
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_agent_crud(_pool: sqlx::PgPool) {
        // Placeholder: full CRUD coverage is in tests/agent_tests.rs
    }
}
