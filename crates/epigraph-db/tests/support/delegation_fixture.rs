//! A delegated run token's database fixture, shared by the API and MCP test
//! crates (`#[path]`-included; a file in a subdirectory is not a test target).
//!
//! Self-contained on purpose: it writes the rows itself, on the harness's
//! superuser pool, except the author-binding allowance, which it makes the way
//! an operator does (migration 149's definer, on a session downgraded to
//! `epigraph_maintenance`), so every guard and the audit trigger run.
//!
//! The shape, all synthetic:
//!
//! * a registered human operator `O`, with its personal group `G`;
//! * a DELEGATOR: an active `service` OAuth client whose agent `D` is on the
//!   allowlist for `O` and holds a membership in `G` (role chosen by the test);
//! * a PRINCIPAL `P`: an agent live-linked to `O` (a writer of `G` through the
//!   link).
#![allow(dead_code)]

use sqlx::PgPool;
use uuid::Uuid;

/// One live delegation (or one the test then breaks).
#[derive(Debug, Clone, Copy)]
pub struct Delegation {
    /// The registered human operator.
    pub operator: Uuid,
    /// The operator's personal group.
    pub operator_group: Uuid,
    /// The delegator client's `oauth_clients.id` (a token's `sub`).
    pub delegator_client: Uuid,
    /// The delegator client's agent (a token's `dlg`).
    pub delegator: Uuid,
    /// The operated agent the token is for (a token's `agent_id`).
    pub principal: Uuid,
}

/// An agent with its personal group and an `admin` membership of it, in the
/// shape `AgentRepository::ensure_personal_group` makes (the canonical viewer
/// fixture's `seed_agent_with_group`).
pub async fn agent_with_group(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    let agent = Uuid::new_v4();
    let pk: Vec<u8> = agent.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("agent row");
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, 'did:epigraph:personal:' || $2::text, ''::bytea, 'personal', $2) \
         RETURNING id",
    )
    .bind(format!("{label}:{agent}"))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("personal group");
    membership(pool, group, agent, "admin").await;
    (agent, group)
}

/// A live membership row of `agent` in `group` with `role`.
pub async fn membership(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("membership row");
}

/// A registered human operator (migration 122 section 1c: an active `human`
/// client of its own AND a `human_operators` row) with its personal group.
pub async fn human_operator(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    let (agent, group) = agent_with_group(pool, label).await;
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id) \
         VALUES ($1, 'delegation fixture operator', 'human', ARRAY['claims:write'], \
                 'active', $2)",
    )
    .bind(format!("delegation-fixture-human-{agent}"))
    .bind(agent)
    .execute(pool)
    .await
    .expect("operator's human client");
    sqlx::query("INSERT INTO human_operators (agent_id, reason) VALUES ($1, 'test fixture')")
        .bind(agent)
        .execute(pool)
        .await
        .expect("human operator row");
    (agent, group)
}

/// A delegator: an active `service` client whose agent holds `role` in
/// `operator_group` (none when `role` is `None`), allowlisted for `operator`
/// when `allow`. Returns `(client row id, agent id)`.
pub async fn delegator(
    pool: &PgPool,
    operator: Uuid,
    operator_group: Uuid,
    role: Option<&str>,
    allow: bool,
) -> (Uuid, Uuid) {
    let agent = Uuid::new_v4();
    let pk: Vec<u8> = agent
        .as_bytes()
        .iter()
        .rev()
        .copied()
        .cycle()
        .take(32)
        .collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("delegator agent");
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, client_type, \
                                    allowed_scopes, granted_scopes, status, agent_id, \
                                    legal_entity_name, legal_contact_email) \
         VALUES ($1, $2, 'delegation fixture delegator', 'service', ARRAY['claims:read'], \
                 ARRAY['claims:read'], 'active', $3, 'Delegation Fixture', \
                 'ops@example.test') \
         RETURNING id",
    )
    .bind(format!("delegation-fixture-{agent}"))
    .bind(pk.as_slice())
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("delegator client");
    if let Some(role) = role {
        membership(pool, operator_group, agent, role).await;
    }
    if allow {
        allow_client(pool, client, operator).await;
    }
    (client, agent)
}

/// Migration 149's allowance of `client` for `operator`, through its definer
/// on a session downgraded to the maintenance role (the operator CLI's path).
pub async fn allow_client(pool: &PgPool, client: Uuid, operator: Uuid) {
    as_maintenance(pool, |conn| {
        Box::pin(async move {
            sqlx::query(
                "SELECT * FROM public.epigraph_allow_author_binding_client($1, $2, 'test')",
            )
            .bind(client)
            .bind(operator)
            .execute(conn)
            .await
            .expect("allow the delegator client");
        })
    })
    .await;
}

/// Migration 149's revoke of `client`'s allowance (final).
pub async fn revoke_allowance(pool: &PgPool, client: Uuid) {
    as_maintenance(pool, |conn| {
        Box::pin(async move {
            sqlx::query(
                "SELECT * FROM public.epigraph_revoke_author_binding_client($1, 'test revoke')",
            )
            .bind(client)
            .execute(conn)
            .await
            .expect("revoke the allowance");
        })
    })
    .await;
}

async fn as_maintenance<F>(pool: &PgPool, f: F)
where
    F: for<'c> FnOnce(
        &'c mut sqlx::PgConnection,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'c>>,
{
    use sqlx::Executor;
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_maintenance")
        .await
        .expect("downgrade to the maintenance role");
    f(&mut conn).await;
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset session authorization");
}

/// An agent live-linked to `operator` (migration 107's link: a not-retired
/// record and a writer membership of the operator's group).
pub async fn linked_principal(pool: &PgPool, operator: Uuid, label: &str) -> Uuid {
    let (agent, _) = agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let out = epigraph_db::AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link the principal");
    assert!(
        out.link_live && out.membership_live,
        "PREMISE: a live link: {out:?}"
    );
    agent
}

/// A fully live delegation.
pub async fn live_delegation(pool: &PgPool, label: &str) -> Delegation {
    let (operator, operator_group) = human_operator(pool, &format!("{label}-operator")).await;
    let (delegator_client, delegator) =
        delegator(pool, operator, operator_group, Some("writer"), true).await;
    let principal = linked_principal(pool, operator, &format!("{label}-principal")).await;
    Delegation {
        operator,
        operator_group,
        delegator_client,
        delegator,
        principal,
    }
}

/// Retire `agent`'s operator link record.
pub async fn retire_link(pool: &PgPool, agent: Uuid) {
    let n = sqlx::query("UPDATE operator_links SET retired = true WHERE agent_id = $1")
        .bind(agent)
        .execute(pool)
        .await
        .expect("retire the link")
        .rows_affected();
    assert_eq!(n, 1, "PREMISE: one link record retired");
}

/// Revoke `agent`'s live membership of `group`.
pub async fn revoke_membership(pool: &PgPool, agent: Uuid, group: Uuid) {
    let n = sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() \
          WHERE agent_id = $1 AND group_id = $2 AND revoked_at IS NULL",
    )
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("revoke the membership")
    .rows_affected();
    assert_eq!(n, 1, "PREMISE: one live membership revoked");
}

/// Set an OAuth client's `status` (`active`, `pending`, `suspended`, `revoked`).
pub async fn set_client_status(pool: &PgPool, client: Uuid, status: &str) {
    sqlx::query("UPDATE oauth_clients SET status = $2 WHERE id = $1")
        .bind(client)
        .bind(status)
        .execute(pool)
        .await
        .expect("set the client status");
}
