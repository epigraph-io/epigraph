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
    /// # Returns
    /// Returns `true` if the agent was deleted, `false` if it didn't exist.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn delete(pool: &PgPool, id: AgentId) -> Result<bool, DbError> {
        let uuid: Uuid = id.into();

        let result = sqlx::query!(
            r#"
            DELETE FROM agents
            WHERE id = $1
            "#,
            uuid
        )
        .execute(pool)
        .await?;

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
}

#[cfg(test)]
mod tests {
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_agent_crud(_pool: sqlx::PgPool) {
        // Placeholder: full CRUD coverage is in tests/agent_tests.rs
    }
}
