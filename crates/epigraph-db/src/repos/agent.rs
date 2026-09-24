//! Agent repository for database operations

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use epigraph_core::{Agent, AgentId};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// One ACTING operator link: the operator's agent id and the id of the
/// operator's personal group, which owns the operated agent's new claims.
///
/// Produced only by [`AgentRepository::operator_actor`] (migration 107's
/// `epigraph_operator_actor`): a not-retired link record, a live
/// `writer`/`admin` membership, and the operator's own personal group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorLink {
    pub operator_id: Uuid,
    pub operator_group_id: Uuid,
}

/// The operator an AUTHOR's claims belong to, from the link record alone.
///
/// Produced only by [`AgentRepository::operator_of_author`] (migration 107's
/// `epigraph_operator_of_author`). Includes RETIRED links, and says nothing
/// about whether the agent may act: that is [`OperatorLink`]'s question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
pub struct AuthorOperator {
    pub operator_id: Uuid,
    pub operator_group_id: Uuid,
    /// The link is retired (migration 107 section 7): the agent never acts for
    /// the operator.
    pub retired: bool,
}

/// What one [`AgentRepository::link_operator`] call did, for the startup log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
pub struct OperatorLinkOutcome {
    /// The operator's personal group.
    pub operator_group_id: Uuid,
    /// This call created the operator's personal group (and seeded the
    /// operator's own `admin` row in it).
    pub group_created: bool,
    /// This call inserted the agent's `writer` membership.
    pub membership_created: bool,
    /// The agent's membership is live after the call. `false` means an operator
    /// revoked it and the call deliberately did not restore it.
    pub membership_live: bool,
    /// This call inserted the `OPERATED_BY` edge.
    pub edge_created: bool,
    /// The link is LIVE after the call, as the authoring and ownership paths
    /// read it (`epigraph_operator_actor` names this operator). This, not
    /// [`Self::membership_live`], is what decides whether the agent authors into
    /// the operator's group: a live membership whose role is no longer
    /// `writer`/`admin` is not a link.
    pub link_live: bool,
    /// The agent's link record is RETIRED (migration 107 section 7). A retired
    /// link is never promoted: the call inserted no membership, and the agent
    /// authors into its own group.
    pub link_retired: bool,
}

/// What one [`AgentRepository::link_retired_agent`] call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
pub struct RetiredLinkOutcome {
    /// The operator's personal group.
    pub operator_group_id: Uuid,
    /// This call created the operator's personal group.
    pub group_created: bool,
    /// This call inserted the `operator_links` row.
    pub link_created: bool,
    /// The agent's link record is retired after the call. `false` means the
    /// agent already had an ACTOR link to this operator, which the call left
    /// exactly as it was (`ON CONFLICT DO NOTHING`).
    pub link_retired: bool,
    /// This call inserted the `OPERATED_BY` edge.
    pub edge_created: bool,
    /// The agent holds a live membership in the operator's group. Never created
    /// or changed by this call — REPORTED, because a retired identity has zero
    /// write authority only while this is `false`.
    pub membership_live: bool,
}

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

/// A Tier-B projection of one `agents` row, narrowed to what a given
/// [`crate::visibility::Viewer`] may see.
///
/// See [`AgentRepository::get_public_profile`] for the rule. The four
/// always-present fields are the ones authorship rendering needs; the three
/// `Option` fields below are `None` when the viewer is not entitled to the
/// agent's PII, which is **indistinguishable from the agent simply not having
/// set them** — deliberately, so the projection is not itself an oracle for
/// "this agent has a private profile".
#[derive(Debug, Clone)]
pub struct AgentPublicProfile {
    pub id: Uuid,
    pub display_name: Option<String>,
    pub public_key: Vec<u8>,
    /// `ed25519` or `derived` (migration 061). Always returned: a caller that
    /// cannot tell a real verifier from the BLAKE3 placeholder will feed the
    /// placeholder to a signature check.
    pub key_kind: String,
    /// `public` or `group` (migration 062). Always returned so a caller can say
    /// *why* the detail fields are empty without a second query.
    pub profile_visibility: String,
    /// `agents.properties` — `full_name`, `affiliations`, `email`. `None` when
    /// the viewer is not entitled to it.
    pub properties: Option<JsonValue>,
    pub orcid: Option<String>,
    pub ror_id: Option<String>,
}

/// Repository for Agent operations
pub struct AgentRepository;

impl AgentRepository {
    /// Create a new agent in the database
    ///
    /// Takes an `Acquire` so the agent row and its `agent.registered` event ride
    /// ONE connection — the caller's transaction when there is one. `&PgPool`
    /// implements `Acquire`, so every existing call site is unchanged.
    ///
    /// # Errors
    /// Returns `DbError::DuplicateKey` if an agent with the same public key already exists.
    /// Returns `DbError::QueryFailed` for other database errors.
    pub async fn create(pool: &PgPool, agent: &Agent) -> Result<Agent, DbError> {
        let mut conn = pool.acquire().await?;
        Self::create_conn(&mut conn, agent).await
    }

    /// [`Self::create`] on a connection the caller owns, so the `agents` row and
    /// its `agent.registered` event ride the caller's transaction. Concrete
    /// `&mut PgConnection` for the reason given on
    /// [`crate::ClaimRepository::create_with_id_if_absent_conn`].
    ///
    /// # Errors
    /// As [`Self::create`].
    pub async fn create_conn(
        conn: &mut sqlx::PgConnection,
        agent: &Agent,
    ) -> Result<Agent, DbError> {
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
        .fetch_one(&mut *conn)
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

        // Fire-and-forget agent.registered event (closes #61). The event log
        // is a separate observability surface and must not roll back the agent
        // on failure — and once the caller can hand us a transaction, "must not
        // roll back" needs a SAVEPOINT rather than a swallowed error, or the
        // failure is merely DEFERRED to a COMMIT that PostgreSQL answers with
        // `ROLLBACK` and no error at all. `publish_or_log_conn` takes it.
        let _ = crate::repos::EventRepository::publish_or_log_conn(
            &mut *conn,
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
    /// # Tenancy: takes an executor, and deliberately takes no `Viewer`
    ///
    /// Widened from `&PgPool` to `E: PgExecutor` by conversion shard 5 so that
    /// the five `routes/political.rs` handlers which call it alongside a
    /// viewer-spliced `PoliticalRepository` read can run BOTH statements on one
    /// viewer-stamped connection. The SQL, its binds and the projected row shape
    /// are unchanged; nothing else about this function was re-derived.
    ///
    /// **MOTIVATION IS NOT REACH, and the reach is wider than the motivation.**
    /// Those five handlers are why the signature moved; they are not the whole
    /// caller set. Ten other PRODUCTION call sites, across six files — four in
    /// `routes/agents.rs`, two in `routes/crud.rs`, and one each in
    /// `routes/claims.rs`, `routes/submit.rs`, `routes/webhooks.rs` (inside
    /// `agent_principal_exists`, a file under a standing do-not-convert hold)
    /// and `epigraph-engine/src/export/prov.rs` — were NOT touched and continue
    /// to pass a `&PgPool`, which still satisfies `E: PgExecutor<'e>`. So no
    /// caller changed behaviour and none needed editing; the count is stated
    /// because this doc is the tree's explanation of why the signature moved,
    /// and a motivation read as an inventory understates what the widening
    /// reaches.
    ///
    /// It has no `Viewer` because there is nothing on `agents` for one to
    /// narrow, and that is a deliberate schema decision rather than an
    /// oversight. `migrations/077_rls_policies.sql` §9 creates
    /// `agents_identity ON public.agents FOR SELECT TO PUBLIC USING (true)` and
    /// states the reason in the migration itself: `agents.id` / `display_name` /
    /// `public_key` "must render authorship on public claims, so the ROW is
    /// universally readable and PostgreSQL has no column-level RLS to narrow
    /// it." That migration names THIS function explicitly among the ones which
    /// "take no `Viewer` and return the full row". The compensating projection —
    /// `profile_visibility` gating `properties`, `orcid` and `ror_id` — lives in
    /// exactly one function, [`Self::get_public_profile`], and the residual is
    /// already on record as `D-PR17-agent-projection-enforced-at-one-call-site`.
    /// Stamping the session GUCs on this read changes no row either way; the
    /// value of the widening is entirely in the SIBLING statement it lets share
    /// the connection.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor))]
    pub async fn get_by_id<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        id: AgentId,
    ) -> Result<Option<Agent>, DbError> {
        let uuid: Uuid = id.into();

        let row = sqlx::query!(
            r#"
            SELECT id, public_key, display_name, created_at, labels, orcid, ror_id
            FROM agents
            WHERE id = $1
            "#,
            uuid
        )
        .fetch_optional(executor)
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
    pub async fn get_by_public_key<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
        .fetch_optional(executor)
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
    /// `DbError::DuplicateKey` if the derived key is squatted by a row that
    /// is not a `derived` OAuth principal, and `DbError::MembershipRevoked` if
    /// the adopted agent holds only a revoked personal-group membership (step
    /// 6 no longer restores it; the RAISE aborts the caller's transaction, so
    /// the client stays unlinked).
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
            //
            // The upsert itself is `public.epigraph_provision_oauth_agent()`
            // (migration 077), a SECURITY DEFINER writer, for the same reason
            // `ensure_personal_group` delegates: this runs pre-authentication,
            // so the only policy arm that could admit it is one keyed on "the
            // session proved nothing" — and because the request path never
            // stamps the session GUCs, that is an app connection's steady state,
            // not a pre-authentication instant. Such an arm was live on every
            // statement and reached every `key_kind = 'derived'` row.
            //
            // The function wraps the SAME statement, `WHERE agents.key_kind =
            // 'derived'` guard included. A `RETURNS uuid` function always yields
            // exactly one row, so the zero-rows case that used to arrive as
            // `None` from `fetch_optional` now arrives as an inner `NULL` — the
            // binding is `(Option<Uuid>,)` and the refusal below is driven off
            // that inner `Option`. Reading it as "a row came back, therefore it
            // worked" would silently drop the guard.
            let (row,): (Option<Uuid>,) =
                sqlx::query_as("SELECT public.epigraph_provision_oauth_agent($1, $2, $3)")
                    .bind(derived.as_slice())
                    .bind(&display_name)
                    .bind(agent_type)
                    .fetch_one(&mut *conn)
                    .await?;

            row.ok_or_else(|| DbError::DuplicateKey {
                entity: format!(
                    "agents.public_key derived for oauth_clients {client_row_id} is held by a \
                     non-derived agent; refusing to adopt it as an OAuth principal"
                ),
            })?
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

    /// Resolve the agent's personal group, provisioning it the FIRST time.
    /// Returns the group id.
    ///
    /// **The statements live in `public.epigraph_ensure_personal_group()`, not
    /// here** — created by migration 077, whose body migration 105 replaced.
    /// They are a bootstrap: the mint runs before any principal exists, so no
    /// membership-keyed policy on `groups` or `group_memberships` can admit
    /// them. Expressing that as a policy arm was tried and was wrong — the only
    /// predicate available to a policy is the row's own shape, and `did_key` is
    /// derived from `created_by_agent_id`, so such an arm references no session
    /// state and grants every connection read of every personal group and every
    /// personal-group membership row, `wrapped_key_share` included. A
    /// `SECURITY DEFINER` function confines the bootstrap to the statements
    /// that need it and leaves the policies with no personal-group arm in
    /// either direction.
    ///
    /// # The contract (migration 105)
    ///
    /// For the (personal group, agent) pair, across every epoch:
    ///
    /// * a LIVE row exists — returns the group and writes NOTHING; the row's
    ///   role is kept, so a deliberate demotion to `reader` stands;
    /// * only REVOKED rows exist — refuses with [`DbError::MembershipRevoked`]
    ///   (SQLSTATE `RVK01`). Reversing a revocation is an operator action;
    /// * no row of any state — provisions the group (if absent) and one live
    ///   epoch-0 `admin` membership.
    ///
    /// Migration 077's body instead ended in `ON CONFLICT (group_id, agent_id,
    /// epoch) DO UPDATE SET revoked_at = NULL, role = 'admin'`, so every call
    /// revived a revoked membership and promoted a demoted one. Any caller that
    /// read "no group" on an UNSTAMPED `epigraph_app` connection — where
    /// `groups_tenancy` hides the group — and then called this reached that
    /// revival: PR-09's `EpiGraphMcpFull::agent_id` (per HTTP session), the
    /// recall audit (#493), and the ingest executor's system agent (#498).
    ///
    /// The refusal is a RAISE, not a NULL return, so a raw-SQL caller cannot
    /// mistake it for success, and it aborts the caller's transaction.
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
    /// # Errors
    /// Returns [`DbError::MembershipRevoked`] if the agent holds only revoked
    /// rows in its personal group, and `DbError::QueryFailed` if a statement
    /// fails.
    #[instrument(skip(conn))]
    pub async fn ensure_personal_group(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
    ) -> Result<Uuid, DbError> {
        let (group_id,): (Uuid,) =
            sqlx::query_as("SELECT public.epigraph_ensure_personal_group($1)")
                .bind(agent_id)
                .fetch_one(&mut *conn)
                .await?;

        Ok(group_id)
    }

    /// "May `agent_id` act for an operator?" — its ACTING operator link, through
    /// migration 107's `epigraph_operator_actor` definer read, or `None`.
    ///
    /// An acting link is an `operator_links` row that is NOT retired AND a live
    /// `writer`/`admin` membership for the agent in the group that row names,
    /// that group being the operator's own personal group. The row is writable
    /// only inside a link function's definer frame (or on a maintenance login),
    /// which is what makes a link unforgeable from an `epigraph_app` session;
    /// the `OPERATED_BY` edge is the graph record and grants nothing, so an HTTP
    /// server's auth-lineage edges (`EpiGraphMcpFull::record_auth_lineage`)
    /// never read as links. The membership half is what lets the operator end
    /// the agent's authority with an ordinary revoke.
    ///
    /// Used for the CALLER side of `require_owner_or_admin` and by
    /// [`crate::repos::ClaimRepository::default_decl_for_author`] — never for
    /// "whose claim is this?", which is [`Self::operator_of_author`].
    ///
    /// `operator_links` is keyed on the agent, so there is at most one.
    ///
    /// # Why a definer function and not a read of the tables
    ///
    /// On an unstamped `epigraph_app` session `groups_tenancy` and
    /// `group_memberships_tenancy` hide every row, so an inline read here would
    /// answer "no operator" on exactly the connections that most need the
    /// answer, and the caller would fall through to minting. The definer read
    /// does not depend on the session's stamp.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the function is absent (a database that has not
    /// applied migration 107) or the read fails. Deliberately NOT mapped to
    /// "no operator": a binary that cannot ask must not author as if the answer
    /// were no.
    pub async fn operator_actor(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
    ) -> Result<Option<OperatorLink>, DbError> {
        let row: Option<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT operator_id, operator_group_id \
               FROM public.epigraph_operator_actor($1)",
        )
        .bind(agent_id)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(row.map(|(operator_id, operator_group_id)| OperatorLink {
            operator_id,
            operator_group_id,
        }))
    }

    /// [`Self::operator_actor`] for a caller holding a pool.
    ///
    /// # Errors
    /// As [`Self::operator_actor`], plus `DbError::ConnectionFailed` if no
    /// connection can be acquired.
    pub async fn operator_actor_pool(
        pool: &PgPool,
        agent_id: Uuid,
    ) -> Result<Option<OperatorLink>, DbError> {
        let mut conn = pool.acquire().await?;
        Self::operator_actor(&mut conn, agent_id).await
    }

    /// "Whose are `agent_id`'s claims?" — the operator named by its link
    /// record, through migration 107's `epigraph_operator_of_author`, or `None`.
    ///
    /// From the `operator_links` row ALONE: RETIRED links are included, and no
    /// membership is consulted, so an operator keeps ownership of what an agent
    /// wrote after revoking or retiring it. This answers ONLY the target side
    /// of `require_owner_or_admin` and refusal-only checks (an HTTP listener
    /// must not serve as a linked signer). It must never decide authoring or
    /// the caller side: a retired identity's key may be exposed, and it holds
    /// no membership, so authoring into its operator's group would be refused
    /// by RLS and acting for the operator would be an escalation.
    ///
    /// # Errors
    /// As [`Self::operator_actor`].
    pub async fn operator_of_author(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
    ) -> Result<Option<AuthorOperator>, DbError> {
        Ok(sqlx::query_as::<_, AuthorOperator>(
            "SELECT operator_id, operator_group_id, retired \
               FROM public.epigraph_operator_of_author($1)",
        )
        .bind(agent_id)
        .fetch_optional(&mut *conn)
        .await?)
    }

    /// [`Self::operator_of_author`] for a caller holding a pool.
    ///
    /// # Errors
    /// As [`Self::operator_of_author`], plus `DbError::ConnectionFailed` if no
    /// connection can be acquired.
    pub async fn operator_of_author_pool(
        pool: &PgPool,
        agent_id: Uuid,
    ) -> Result<Option<AuthorOperator>, DbError> {
        let mut conn = pool.acquire().await?;
        Self::operator_of_author(&mut conn, agent_id).await
    }

    /// "Does any agent name `agent_id` as its operator?", through migration
    /// 107's `epigraph_operates_agents` (retired links included).
    ///
    /// REFUSAL-ONLY (107 section 9): an HTTP listener must not serve as a
    /// signer that is anyone's operator, because on an unauthenticated HTTP
    /// transport every anonymous caller IS the signer, and would then satisfy
    /// "caller is the operator of the claim's author". Never use it to GRANT.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails (e.g. a database without 107).
    pub async fn operates_agents(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
    ) -> Result<bool, DbError> {
        Ok(
            sqlx::query_scalar::<_, bool>("SELECT public.epigraph_operates_agents($1)")
                .bind(agent_id)
                .fetch_one(&mut *conn)
                .await?,
        )
    }

    /// [`Self::operates_agents`] for a caller holding a pool.
    ///
    /// # Errors
    /// As [`Self::operates_agents`], plus `DbError::ConnectionFailed` if no
    /// connection can be acquired.
    pub async fn operates_agents_pool(pool: &PgPool, agent_id: Uuid) -> Result<bool, DbError> {
        let mut conn = pool.acquire().await?;
        Self::operates_agents(&mut conn, agent_id).await
    }

    /// Record that `agent_id` is operated by `operator_id`, through migration
    /// 107's `epigraph_link_operator`.
    ///
    /// **The caller's connection privilege is the authorization.** The function
    /// is EXECUTE-able by `epigraph_maintenance` (and superusers) only; on an
    /// `epigraph_app` connection this returns the database's `42501 permission
    /// denied` as `DbError::QueryFailed`. It is never skipped or retried on a
    /// different connection — a declared link the process cannot record must be
    /// visible, not absent.
    ///
    /// Recorded once: an existing membership row of any state for the pair is
    /// left untouched, so a link an operator revoked stays revoked
    /// ([`OperatorLinkOutcome::membership_live`] and
    /// [`OperatorLinkOutcome::link_live`] report `false`). See the migration's
    /// section 3.
    ///
    /// # Errors
    /// `DbError::QueryFailed` for a permission refusal, a missing agent, a
    /// self-link, an operator that is itself operated, or an agent already
    /// linked to a DIFFERENT live operator; the database message names which.
    pub async fn link_operator(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
        operator_id: Uuid,
    ) -> Result<OperatorLinkOutcome, DbError> {
        Ok(sqlx::query_as::<_, OperatorLinkOutcome>(
            "SELECT operator_group_id, group_created, membership_created, membership_live, \
                    edge_created, link_live, link_retired \
               FROM public.epigraph_link_operator($1, $2)",
        )
        .bind(agent_id)
        .bind(operator_id)
        .fetch_one(&mut *conn)
        .await?)
    }

    /// Record that the RETIRED agent `agent_id`'s claims belong to
    /// `operator_id`, through migration 107's `epigraph_link_retired_agent`.
    ///
    /// Writes the `operator_links` row with `retired = true` and the
    /// `OPERATED_BY` edge, and creates NO membership: a retired identity's key
    /// may be publicly recomputable or exposed, so linking it must confer zero
    /// write authority. The operator (and the operator's live actors) then own
    /// its claims through `require_owner_or_admin`'s author resolution; the
    /// retired agent itself can never act for the operator.
    ///
    /// Same authorization as [`Self::link_operator`]: EXECUTE-able by
    /// `epigraph_maintenance` (and superusers) only. Idempotent, and never
    /// changes an existing row or membership.
    ///
    /// # Errors
    /// `DbError::QueryFailed` for a permission refusal, a missing agent, a
    /// self-link, an operator that is itself operated, an agent that already
    /// operates others or is linked to a DIFFERENT operator, or an operator
    /// group the operator did not create; the database message names which.
    pub async fn link_retired_agent(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
        operator_id: Uuid,
    ) -> Result<RetiredLinkOutcome, DbError> {
        Ok(sqlx::query_as::<_, RetiredLinkOutcome>(
            "SELECT operator_group_id, group_created, link_created, link_retired, \
                    edge_created, membership_live \
               FROM public.epigraph_link_retired_agent($1, $2)",
        )
        .bind(agent_id)
        .bind(operator_id)
        .fetch_one(&mut *conn)
        .await?)
    }

    /// Tier-B projection of one agent, filtered by what `viewer` may see.
    ///
    /// `agents` is deliberately **not** a tenancy-partitioned table: authorship
    /// must render on a public claim, so the row itself stays readable and
    /// migration 077's policy on it is `USING (true)` with an explicit
    /// `-- VISIBILITY-EXEMPT:` marker. What is *not* universally readable is the
    /// PII the row carries — `agents.properties` holds `full_name`, `orcid`,
    /// `affiliations` and `email` (migration 001).
    ///
    /// PostgreSQL has no column-level RLS, so the narrowing is a **repo-layer
    /// projection**: `id`, `display_name`, `public_key` and `key_kind` are
    /// always returned; [`AgentPublicProfile::properties`], `orcid` and `ror_id`
    /// are `None` unless one of three things holds —
    ///
    /// 1. `profile_visibility = 'public'` (migration 062's default), or
    /// 2. the viewer **is** this agent, or
    /// 3. the viewer shares a live group with it.
    ///
    /// A bypass viewer sees everything, as everywhere else.
    ///
    /// The decision is made in SQL, in the same round trip as the row, so there
    /// is no window in which the caller holds the PII and has not yet decided
    /// whether it may show it.
    ///
    /// Runtime `sqlx::query_as`, like every other query in this file, so no
    /// `.sqlx/` cache entry is needed. `schema_contract.rs` is what pins the
    /// columns it names.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_public_profile<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        id: Uuid,
    ) -> Result<Option<AgentPublicProfile>, DbError> {
        type Row = (
            Uuid,
            Option<String>,
            Vec<u8>,
            String,
            String,
            bool,
            JsonValue,
            Option<String>,
            Option<String>,
        );

        let row: Option<Row> = sqlx::query_as(
            r#"
            SELECT a.id,
                   a.display_name,
                   a.public_key,
                   a.key_kind,
                   a.profile_visibility,
                   (   $4::bool
                    OR a.profile_visibility = 'public'
                    OR ($2::uuid IS NOT NULL AND a.id = $2::uuid)
                    OR EXISTS (SELECT 1 FROM group_memberships gm
                                WHERE gm.agent_id = a.id
                                  AND gm.revoked_at IS NULL
                                  AND gm.group_id = ANY($3::uuid[]))
                   ) AS may_see_details,
                   a.properties,
                   a.orcid,
                   a.ror_id
            FROM agents a
            WHERE a.id = $1
            "#,
        )
        .bind(id)
        .bind(viewer.principal())
        .bind(viewer.group_bind().unwrap_or(&[]))
        .bind(viewer.is_bypass())
        .fetch_optional(executor)
        .await?;

        Ok(row.map(
            |(
                id,
                display_name,
                public_key,
                key_kind,
                profile_visibility,
                may_see_details,
                properties,
                orcid,
                ror_id,
            )| AgentPublicProfile {
                id,
                display_name,
                public_key,
                key_kind,
                profile_visibility,
                properties: may_see_details.then_some(properties),
                orcid: if may_see_details { orcid } else { None },
                ror_id: if may_see_details { ror_id } else { None },
            },
        ))
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
