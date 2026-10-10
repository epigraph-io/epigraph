//! Migration 149: the author-binding allowlist. A third way for a writing
//! agent to be BOUND (after a registered human and a live operator link): the
//! agent of an OAuth client the operator NAMED on the maintenance-only
//! registry `author_binding_clients`, bound to the registered human that row
//! names, while every read-time condition holds.
//!
//! Privilege, valve and application-role arms run under `fixture::as_role`
//! (`SET SESSION AUTHORIZATION`): the harness is a superuser, so
//! `epigraph_bypass()` is true on the default pool and a default-pool
//! privilege test would be vacuous.
//!
//! Read-time predicates are tested with rows PLANTED past the guard
//! (`session_replication_role = replica`, which skips user triggers), so a
//! mutation of the read helper cannot hide behind the insert guard. Replica
//! mode also skips FK enforcement, so every planted row uses real, existing
//! ids, and [`plant`] asserts that they resolve before it writes.
//!
//! `write_as` stamps the given groups as readable AND writable, so row
//! security admits the row and the claims trigger alone decides: every Ok it
//! gives is a trigger truth, not a statement about row security.
//!
//! The binding reads use the registered system-agent table when it exists
//! (`public.system_agents`), softly: [`ensure_system_agents`] creates a
//! stand-in carrying the columns [`plant_system_agent`] writes on a database
//! that does not carry it, and the plant writes a row the real table accepts,
//! so the system-agent cases run with or without that migration.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::AgentRepository;
use sqlx::PgPool;
use uuid::Uuid;

const OPL01: &str = "OPL01";
const OPL02: &str = "OPL02";
const INSUFFICIENT_PRIVILEGE: &str = "42501";
const OBJECT_STATE: &str = "55000";
const NULL_VALUE: &str = "22004";
const ALLOWED_EVENT: &str = "platform.author_binding_client_allowed";
const REVOKED_EVENT: &str = "platform.author_binding_client_revoked";
const CLIENT_ALLOWLIST: &str = "client_allowlist";
/// The link guard's message fragment; the MCP stdio self-link maps on it.
const LINK_GUARD_FRAGMENT: &str = "on the author-binding allowlist";

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

fn code_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> Option<String> {
    r.as_ref().err().and_then(sqlstate)
}

// ---------------------------------------------------------------------
// Copied from `operator_binding.rs` (`insert_claim`, `as_app_stamped`,
// `write_as`), where they are private. Copied rather than moved, so that
// file stays untouched by this migration's change.
// ---------------------------------------------------------------------

/// A `('public', group)` claim by `agent`, on whatever connection `exec` is.
async fn insert_claim<'e, E>(exec: E, agent: Uuid, group: Uuid) -> Result<Uuid, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let id = Uuid::new_v4();
    let hash = id.as_bytes().repeat(2);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("author binding allowlist probe {id}"))
    .bind(hash)
    .bind(agent)
    .bind(group)
    .execute(exec)
    .await?;
    Ok(id)
}

/// Run `f` on a connection that is `epigraph_app`, stamped as `principal` with
/// `groups` as its read AND writable set, exactly the three GUCs `ScopedPool`
/// stamps; the stamp is cleared and the role reset afterwards.
async fn as_app_stamped<F, Fut, T>(pool: &PgPool, principal: Uuid, groups: &[Uuid], f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    let set = groups
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $2, false)",
        )
        .bind(principal.to_string())
        .bind(&set)
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let (mut conn, out) = f(conn).await;
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, out)
    })
    .await
}

/// A `('public', group)` claim by `author` inserted on an `epigraph_app`
/// connection stamped as `writer` with `groups` readable AND writable.
async fn write_as(
    pool: &PgPool,
    writer: Uuid,
    groups: &[Uuid],
    author: Uuid,
    owner: Uuid,
) -> Result<Uuid, sqlx::Error> {
    as_app_stamped(pool, writer, groups, |mut conn| async move {
        let r = insert_claim(&mut *conn, author, owner).await;
        (conn, r)
    })
    .await
}

// ---------------------------------------------------------------------
// Fixtures local to this file.
// ---------------------------------------------------------------------

/// [`write_as`] with the session's binding valve open
/// (`epigraph.operator_link_enforcement = 'off'`), reset afterwards.
async fn valve_write(
    pool: &PgPool,
    writer: Uuid,
    groups: &[Uuid],
    author: Uuid,
    owner: Uuid,
) -> Result<Uuid, sqlx::Error> {
    as_app_stamped(pool, writer, groups, |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', 'off', false)")
            .execute(&mut *conn)
            .await
            .expect("valve");
        let r = insert_claim(&mut *conn, author, owner).await;
        sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', '', false)")
            .execute(&mut *conn)
            .await
            .expect("valve reset");
        (conn, r)
    })
    .await
}

/// Arm the database as the maintenance role would.
async fn arm(pool: &PgPool) {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("the maintenance role arms");
        (conn, ())
    })
    .await;
}

/// An agent, its personal group, and one OAuth client for it.
#[derive(Clone, Copy, Debug)]
struct Client {
    id: Uuid,
    agent: Uuid,
    group: Uuid,
}

/// A new OAuth client row for `agent` (`agent` may be `None`: a client that
/// has never minted). A service client carries the legal fields its CHECK
/// requires; an agent client needs `owner` (`agents_must_have_owner`).
async fn new_client(
    pool: &PgPool,
    agent: Option<Uuid>,
    client_type: &str,
    status: &str,
    owner: Option<Uuid>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, owner_id, legal_entity_name, \
                                    legal_contact_email) \
         VALUES ($1, 'allowlist fixture client', $2, ARRAY['claims:write'], $3, $4, $5, \
                 'Fixture Org', 'fixture@example.invalid') \
         RETURNING id",
    )
    .bind(format!("allowlist-{}", Uuid::new_v4()))
    .bind(client_type)
    .bind(status)
    .bind(agent)
    .bind(owner)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{client_type} client: {e}"))
}

/// A fresh agent with its personal group and an ACTIVE service client.
async fn service(pool: &PgPool, label: &str) -> Client {
    let (agent, group) = fixture::seed_agent_with_group(pool, label).await;
    let id = new_client(pool, Some(agent), "service", "active", None).await;
    Client { id, agent, group }
}

/// A fresh agent with its personal group and an ACTIVE agent-type client
/// whose `owner_id` is `owner` (an `oauth_clients.id`).
async fn agent_typed(pool: &PgPool, label: &str, owner: Uuid) -> Client {
    let (agent, group) = fixture::seed_agent_with_group(pool, label).await;
    let id = new_client(pool, Some(agent), "agent", "active", Some(owner)).await;
    Client { id, agent, group }
}

/// The `oauth_clients.id` of `agent`'s (first) human client.
async fn human_client_of(pool: &PgPool, agent: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human' \
          ORDER BY created_at LIMIT 1",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("the human's client")
}

async fn set_status(pool: &PgPool, client: Uuid, status: &str) {
    sqlx::query("UPDATE oauth_clients SET status = $2 WHERE id = $1")
        .bind(client)
        .bind(status)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("client status -> {status}: {e}"));
}

/// What the allow definer returns.
#[derive(Debug, PartialEq, Eq)]
struct Allowed {
    allowed_now: bool,
    agent_id: Uuid,
    operator_id: Uuid,
    effective_binding: Option<String>,
}

async fn allow_on(
    conn: &mut sqlx::PgConnection,
    client: Uuid,
    operator: Uuid,
    reason: &str,
) -> Result<Allowed, sqlx::Error> {
    sqlx::query_as::<_, (bool, Uuid, Uuid, Option<String>)>(
        "SELECT allowed_now, agent_id, operator_id, effective_binding \
           FROM public.epigraph_allow_author_binding_client($1, $2, $3)",
    )
    .bind(client)
    .bind(operator)
    .bind(reason)
    .fetch_one(&mut *conn)
    .await
    .map(
        |(allowed_now, agent_id, operator_id, effective_binding)| Allowed {
            allowed_now,
            agent_id,
            operator_id,
            effective_binding,
        },
    )
}

/// The maintenance role allows `client` for `operator`.
async fn allow(
    pool: &PgPool,
    client: Uuid,
    operator: Uuid,
    reason: &str,
) -> Result<Allowed, sqlx::Error> {
    let reason = reason.to_string();
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = allow_on(&mut conn, client, operator, &reason).await;
        (conn, r)
    })
    .await
}

/// The maintenance role revokes `client`'s allowance.
async fn revoke(pool: &PgPool, client: Uuid, reason: &str) -> Result<bool, sqlx::Error> {
    let reason = reason.to_string();
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query_scalar::<_, bool>(
            "SELECT revoked_now FROM public.epigraph_revoke_author_binding_client($1, $2)",
        )
        .bind(client)
        .bind(&reason)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

/// `(epigraph_author_binding(a), epigraph_human_of(a, true), epigraph_human_of(a, false))`.
type Binding = (Option<String>, Option<Uuid>, Option<Uuid>);

async fn binding(pool: &PgPool, agent: Option<Uuid>) -> Binding {
    sqlx::query_as(
        "SELECT public.epigraph_author_binding($1), public.epigraph_human_of($1, true), \
                public.epigraph_human_of($1, false)",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("binding reads")
}

fn allowlisted(operator: Uuid) -> Binding {
    (
        Some(CLIENT_ALLOWLIST.to_string()),
        Some(operator),
        Some(operator),
    )
}

const UNBOUND: Binding = (None, None, None);

/// `security_events` rows of `event_type` naming `client`.
async fn events(pool: &PgPool, event_type: &str, client: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type = $1 AND details->>'client_id' = $2::text",
    )
    .bind(event_type)
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("events")
}

/// Assert that each id names an existing row of `table` (planted rows bypass
/// FK enforcement, so an impossible row would read "unbound" for the wrong
/// reason).
async fn assert_exists(pool: &PgPool, table: &str, ids: &[Uuid]) {
    for id in ids {
        let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE id = $1"))
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("exists");
        assert_eq!(n, 1, "the planted id {id} must name a real {table} row");
    }
}

/// Plant an allowance row PAST the guard (replica mode: no user triggers, so
/// no guard, no audit). `revoked` plants it already revoked.
async fn plant(pool: &PgPool, client: Uuid, agent: Uuid, operator: Uuid, revoked: bool) {
    assert_exists(pool, "oauth_clients", &[client]).await;
    assert_exists(pool, "agents", &[agent, operator]).await;
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .expect("replica");
    sqlx::query(
        "INSERT INTO author_binding_clients (client_id, agent_id, operator_id, reason, \
                                             revoked_at, revoked_by, revoked_reason) \
         VALUES ($1, $2, $3, 'planted', \
                 CASE WHEN $4 THEN now() END, CASE WHEN $4 THEN 'planted' END, \
                 CASE WHEN $4 THEN 'planted' END)",
    )
    .bind(client)
    .bind(agent)
    .bind(operator)
    .bind(revoked)
    .execute(&mut *tx)
    .await
    .expect("plant an allowance");
    tx.commit().await.expect("commit");
}

/// Plant an `operator_links` row past 107/122's guards (replica mode).
async fn plant_link(pool: &PgPool, agent: Uuid, operator: Uuid, group: Uuid, retired: bool) {
    assert_exists(pool, "agents", &[agent, operator]).await;
    assert_exists(pool, "groups", &[group]).await;
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .expect("replica");
    sqlx::query(
        "INSERT INTO operator_links (agent_id, operator_id, operator_group_id, retired) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(agent)
    .bind(operator)
    .bind(group)
    .bind(retired)
    .execute(&mut *tx)
    .await
    .expect("plant a link");
    tx.commit().await.expect("commit");
}

/// The registered system-agent table, or a stand-in with its `agent_id`
/// column where the database does not carry one. The maintenance role (which
/// owns the 149 definers that read it) is granted SELECT on the stand-in.
async fn ensure_system_agents(pool: &PgPool) {
    sqlx::raw_sql(
        "DO $$ BEGIN \
           IF to_regclass('public.system_agents') IS NULL THEN \
             CREATE TABLE public.system_agents ( \
               role text PRIMARY KEY, \
               agent_id uuid NOT NULL REFERENCES public.agents(id), \
               registered_public_key bytea NOT NULL, \
               reason text NOT NULL); \
             GRANT SELECT ON public.system_agents TO epigraph_maintenance; \
           END IF; \
         END $$",
    )
    .execute(pool)
    .await
    .expect("system_agents");
}

/// Plant the `workflow-ingest` `system_agents` row for `agent` past any guard
/// (replica mode skips triggers, not constraints). The row satisfies the
/// system-agent registry migration's own table (its closed role vocabulary,
/// the registered key, a reason), so the same plant runs whether that
/// migration is in the chain or the stand-in above is; the registry's definer
/// cannot be used, because it refuses an agent that is an OAuth client's
/// principal, which these tests set up on purpose. One plant per test (the
/// role is the primary key; each `sqlx::test` has its own database).
async fn plant_system_agent(pool: &PgPool, agent: Uuid) {
    ensure_system_agents(pool).await;
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .expect("replica");
    let planted = sqlx::query(
        "INSERT INTO public.system_agents (role, agent_id, registered_public_key, reason) \
         SELECT 'workflow-ingest', a.id, a.public_key, 'allowlist test plant' \
           FROM public.agents a WHERE a.id = $1",
    )
    .bind(agent)
    .execute(&mut *tx)
    .await
    .expect("plant a system agent");
    assert_eq!(planted.rows_affected(), 1, "plant: agent {agent} exists");
    tx.commit().await.expect("commit");
}

fn assert_refused<T: std::fmt::Debug>(
    r: &Result<T, sqlx::Error>,
    code: &str,
    fragment: &str,
    what: &str,
) {
    match r {
        Ok(v) => panic!("{what}: expected {code}, got Ok({v:?})"),
        Err(e) => {
            assert_eq!(sqlstate(e).as_deref(), Some(code), "{what}: {e}");
            assert!(
                e.to_string().contains(fragment),
                "{what}: the refusal must name its cause ({fragment:?}): {e}"
            );
        }
    }
}

// =====================================================================
// T1: an empty registry changes no binding answer.
// =====================================================================

fn up_to_below(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < version)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

/// Applying 149 over a populated database changes no answer of
/// `epigraph_author_binding` or `epigraph_human_of` (either `p_live_only`)
/// while the registry is empty, for every shape of agent: a human, a live
/// link, a retired link, an unbound agent, a service client's agent, an agent
/// client OWNED by a human's client (the rejected owner-rule shape), a human
/// whose client is suspended, and a NULL argument.
///
/// Verified to fail: the read helper keyed on `oauth_clients.owner_id`
/// (an owner rule) -> A reads bound; `NOT l.retired` dropped from the
/// re-bodied `epigraph_author_binding` -> R reads `live_link`.
#[sqlx::test(migrations = false)]
async fn an_empty_allowlist_changes_no_binding_answer(pool: PgPool) {
    migrate(&pool, &up_to_below(149)).await;

    let (h, _) = fixture::seed_human_operator(&pool, "human").await;
    let h_client = human_client_of(&pool, h).await;
    let (l, _) = fixture::seed_agent_with_group(&pool, "live").await;
    let (r, _) = fixture::seed_agent_with_group(&pool, "retired").await;
    let (u, _) = fixture::seed_agent_with_group(&pool, "unbound").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, l, h)
            .await
            .expect("live link");
        AgentRepository::link_retired_agent(&mut conn, r, h)
            .await
            .expect("retired link");
    }
    let s = service(&pool, "service").await;
    let a = agent_typed(&pool, "owned-agent", h_client).await;
    let (hs, _) = fixture::seed_human_operator(&pool, "human-suspended").await;
    let hs_client = human_client_of(&pool, hs).await;
    set_status(&pool, hs_client, "suspended").await;

    let population: Vec<(&str, Option<Uuid>)> = vec![
        ("H", Some(h)),
        ("L", Some(l)),
        ("R", Some(r)),
        ("U", Some(u)),
        ("S", Some(s.agent)),
        ("A", Some(a.agent)),
        ("Hs", Some(hs)),
        ("NULL", None),
    ];
    let mut before = Vec::new();
    for (name, agent) in &population {
        before.push((*name, binding(&pool, *agent).await));
    }

    migrate(&pool, &MIGRATOR).await;
    let mut after = Vec::new();
    for (name, agent) in &population {
        after.push((*name, binding(&pool, *agent).await));
    }
    assert_eq!(
        after, before,
        "149 changed a binding answer over an empty registry"
    );

    // CALIBRATION: the population spans every answer shape.
    let of = |n: &str| before.iter().find(|(k, _)| *k == n).expect(n).1.clone();
    assert_eq!(of("H").0.as_deref(), Some("human_operator"));
    assert_eq!(of("L").0.as_deref(), Some("live_link"));
    assert_eq!(
        of("R"),
        (None, None, Some(h)),
        "a retired link: human_of(R, false) only"
    );
    assert_eq!(of("U"), UNBOUND);
    assert_eq!(
        of("A"),
        UNBOUND,
        "an owned agent client is not bound by its owner"
    );
    assert_eq!(of("NULL"), UNBOUND);
}

// =====================================================================
// T2 / T2b: an allowlisted client's agent is bound to the row's operator.
// =====================================================================

/// The allowlisted agent of an active SERVICE client is bound to its row's
/// operator: it writes a claim authored by that operator's live-linked agent
/// into the operator's group (OPL01 before the allowance), but not into its
/// own personal group, nor naming another human's agent (OPL02). A second
/// client allowed to a second human is bound to THAT human.
///
/// Verified to fail: the `client_allowlist` arm removed from
/// `epigraph_author_binding` (step 4: OPL01); the ELSE arm removed from
/// `epigraph_human_of` (step 4: OPL02, and step 5 lands); a helper that
/// returns the first registered human rather than the row's (step 7).
#[sqlx::test(migrations = "../../migrations")]
async fn an_allowlisted_service_client_binds_its_agent_to_the_operator(pool: PgPool) {
    let (h, g_h) = fixture::seed_human_operator(&pool, "human-h").await;
    let (b, g_b) = fixture::seed_human_operator(&pool, "human-b").await;
    let (l, _) = fixture::seed_agent_with_group(&pool, "h-agent-l").await;
    let (l_b, _) = fixture::seed_agent_with_group(&pool, "b-agent-lb").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, l, h)
            .await
            .expect("l -> h");
        AgentRepository::link_operator(&mut conn, l_b, b)
            .await
            .expect("l_b -> b");
    }
    let s = service(&pool, "service-s").await;
    arm(&pool).await;

    // 1. CALIBRATION: unbound before the allowance.
    let r = write_as(&pool, s.agent, &[g_h], l, g_h).await;
    assert_eq!(code_of(&r).as_deref(), Some(OPL01), "{r:?}");

    // 2-3. Allowed: bound to H.
    let a = allow(&pool, s.id, h, "test").await.expect("allow");
    assert!(a.allowed_now);
    assert_eq!(a.agent_id, s.agent, "the agent is pinned from the client");
    assert_eq!(a.operator_id, h);
    assert_eq!(binding(&pool, Some(s.agent)).await, allowlisted(h));

    // 4. The host-packet shape: S writes, author L, owner G_H.
    write_as(&pool, s.agent, &[g_h], l, g_h)
        .await
        .expect("the allowlisted writer writes its operator's agent's claim");
    // 5. As itself into its own personal group: H does not write it.
    let r = write_as(&pool, s.agent, &[s.group], s.agent, s.group).await;
    assert_eq!(code_of(&r).as_deref(), Some(OPL02), "{r:?}");
    // 6. Naming another human's agent.
    let r = write_as(&pool, s.agent, &[g_h], l_b, g_h).await;
    assert_eq!(code_of(&r).as_deref(), Some(OPL02), "{r:?}");

    // 7. A second service client (owner NULL) allowed to B is B's.
    let s2 = service(&pool, "service-s2").await;
    allow(&pool, s2.id, b, "test").await.expect("allow s2");
    assert_eq!(binding(&pool, Some(s2.agent)).await, allowlisted(b));
    write_as(&pool, s2.agent, &[g_b], l_b, g_b)
        .await
        .expect("S2 writes B's agent's claim in B's group");
    let r = write_as(&pool, s2.agent, &[g_h], l, g_h).await;
    assert_eq!(code_of(&r).as_deref(), Some(OPL02), "{r:?}");
}

/// An AGENT-type client binds the same way, and to the row's operator, not
/// to the human whose client OWNS it (the rejected owner rule).
///
/// Verified to fail: `client_type IN ('service','agent')` narrowed to
/// `'service'`; a helper returning the owner client's agent.
#[sqlx::test(migrations = "../../migrations")]
async fn an_allowlisted_agent_type_client_binds_too(pool: PgPool) {
    let (h, g_h) = fixture::seed_human_operator(&pool, "human-h").await;
    let (h2, g_h2) = fixture::seed_human_operator(&pool, "human-h2").await;
    let (l, _) = fixture::seed_agent_with_group(&pool, "h-agent-l").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, l, h)
            .await
            .expect("l -> h");
    }
    let a = agent_typed(&pool, "agent-a", human_client_of(&pool, h2).await).await;
    arm(&pool).await;

    let r = write_as(&pool, a.agent, &[g_h], l, g_h).await;
    assert_eq!(code_of(&r).as_deref(), Some(OPL01), "CALIBRATION: {r:?}");
    let allowed = allow(&pool, a.id, h, "test").await.expect("allow");
    assert_eq!(allowed.agent_id, a.agent);
    assert_eq!(
        binding(&pool, Some(a.agent)).await,
        allowlisted(h),
        "H, not H2"
    );
    write_as(&pool, a.agent, &[g_h], l, g_h)
        .await
        .expect("into H's group");
    let r = write_as(&pool, a.agent, &[g_h2], a.agent, g_h2).await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some(OPL02),
        "into H2's group: {r:?}"
    );
}

// =====================================================================
// T3: every unmet condition reads unbound.
// =====================================================================

/// Each read-time condition of arm (c), broken alone on a row planted past
/// the guard, reads `(author_binding, human_of(.,true), human_of(.,false))`
/// as below. One case per conjunct of `epigraph_allowlisted_operator`:
///
/// | case | conjunct killed |
/// |---|---|
/// | a | `r.revoked_at IS NULL` |
/// | b, c, d | `c.status = 'active'` |
/// | e | `c.client_type IN ('service','agent')` |
/// | f, g, h | `epigraph_is_human_operator(r.operator_id)` |
/// | i | `c.agent_id = p_agent` |
/// | j, k | the agent holds a link (`NOT EXISTS ... l.agent_id = p_agent`) |
/// | m | the operator holds a link as an agent |
/// | n | the agent operates another agent |
/// | o | another non-revoked client has the agent |
/// | p | the agent is a registered system agent |
/// | q | the `to_regclass` guard: no system-agent table, no error |
///
/// The explicit link arm of `epigraph_human_of` (a link row of any state
/// decides) is backed by the helper's own link conjunct: with either one in
/// place, (j) reads `(NULL, NULL, H2)`, so no case kills the arm alone.
///
/// The helper's `NOT epigraph_is_human_operator(p_agent)` conjunct is reached
/// directly (case l). It is implied by the other-client conjunct (a human
/// operator holds an active human client besides the allowlisted one), so no
/// case kills it alone; it is kept as a stated precondition.
#[sqlx::test(migrations = "../../migrations")]
async fn every_unmet_condition_reads_unbound(pool: PgPool) {
    let (h, g_h) = fixture::seed_human_operator(&pool, "human-h").await;
    let (h2, g_h2) = fixture::seed_human_operator(&pool, "human-h2").await;
    let (l, _) = fixture::seed_agent_with_group(&pool, "h-agent-l").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, l, h)
            .await
            .expect("l -> h");
    }
    arm(&pool).await;

    // CALIBRATION: a fully valid planted row reads allowlisted.
    let calib = service(&pool, "calibration").await;
    plant(&pool, calib.id, calib.agent, h, false).await;
    assert_eq!(binding(&pool, Some(calib.agent)).await, allowlisted(h));

    // A fresh service client with a VALID planted row naming `op`, asserted
    // bound before its defect is applied.
    let valid = |label: &'static str, op: Uuid| {
        let pool = pool.clone();
        async move {
            let s = service(&pool, label).await;
            plant(&pool, s.id, s.agent, op, false).await;
            assert_eq!(
                binding(&pool, Some(s.agent)).await,
                allowlisted(op),
                "{label}: bound before the defect"
            );
            s
        }
    };

    // (a) the row is revoked.
    let sa = service(&pool, "a-revoked-row").await;
    plant(&pool, sa.id, sa.agent, h, true).await;
    assert_eq!(binding(&pool, Some(sa.agent)).await, UNBOUND, "(a)");
    let r = write_as(&pool, sa.agent, &[g_h], l, g_h).await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some(OPL01),
        "(a) armed write: {r:?}"
    );

    // (b) the client is suspended; a privileged re-activation re-binds.
    let sb = valid("b-suspended", h).await;
    set_status(&pool, sb.id, "suspended").await;
    assert_eq!(binding(&pool, Some(sb.agent)).await, UNBOUND, "(b)");
    let r = write_as(&pool, sb.agent, &[g_h], l, g_h).await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some(OPL01),
        "(b) armed write: {r:?}"
    );
    set_status(&pool, sb.id, "active").await;
    assert_eq!(
        binding(&pool, Some(sb.agent)).await,
        allowlisted(h),
        "(b) re-activated"
    );

    // (c) / (d) revoked / pending.
    for (label, status) in [("c-revoked", "revoked"), ("d-pending", "pending")] {
        let s = valid(label, h).await;
        // `pending` is reached from `active` only by a privileged session.
        set_status(&pool, s.id, status).await;
        assert_eq!(binding(&pool, Some(s.agent)).await, UNBOUND, "{label}");
    }

    // (e) a human-type client of an unregistered agent.
    let (e_agent, _) = fixture::seed_agent_with_group(&pool, "e-human-client").await;
    let e_client = new_client(&pool, Some(e_agent), "human", "active", None).await;
    plant(&pool, e_client, e_agent, h, false).await;
    assert_eq!(binding(&pool, Some(e_agent)).await, UNBOUND, "(e)");

    // (f) the operator holds a human client but no registry row.
    let (o_f, _) = fixture::seed_agent_with_group(&pool, "f-unregistered-operator").await;
    new_client(&pool, Some(o_f), "human", "active", None).await;
    let sf = service(&pool, "f").await;
    plant(&pool, sf.id, sf.agent, o_f, false).await;
    assert_eq!(binding(&pool, Some(sf.agent)).await, UNBOUND, "(f)");

    // (g) the operator's registration is revoked.
    let (h_g, _) = fixture::seed_human_operator(&pool, "g-human").await;
    let sg = valid("g", h_g).await;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_revoke_human_operator($1, 'left')")
            .bind(h_g)
            .execute(&mut *conn)
            .await
            .expect("revoke the human");
        (conn, ())
    })
    .await;
    assert_eq!(binding(&pool, Some(sg.agent)).await, UNBOUND, "(g)");

    // (h) the operator's recorded human client is suspended.
    let (h_h, _) = fixture::seed_human_operator(&pool, "h-human").await;
    let sh = valid("h", h_h).await;
    set_status(&pool, human_client_of(&pool, h_h).await, "suspended").await;
    assert_eq!(binding(&pool, Some(sh.agent)).await, UNBOUND, "(h)");

    // (i) the row's agent is not the client's agent.
    let si = service(&pool, "i-client").await;
    let (i_other, _) = fixture::seed_agent_with_group(&pool, "i-other-agent").await;
    plant(&pool, si.id, i_other, h, false).await;
    assert_eq!(
        binding(&pool, Some(i_other)).await,
        UNBOUND,
        "(i) the row's agent"
    );
    assert_eq!(
        binding(&pool, Some(si.agent)).await,
        UNBOUND,
        "(i) the client's agent"
    );

    // (j) a RETIRED link to H2 decides: never H through the allowlist.
    let sj = valid("j", h).await;
    plant_link(&pool, sj.agent, h2, g_h2, true).await;
    assert_eq!(
        binding(&pool, Some(sj.agent)).await,
        (None, None, Some(h2)),
        "(j) the precedence trap"
    );

    // (k) a LIVE link to H2 decides.
    let sk = valid("k", h).await;
    plant_link(&pool, sk.agent, h2, g_h2, false).await;
    assert_eq!(
        binding(&pool, Some(sk.agent)).await,
        (Some("live_link".to_string()), Some(h2), Some(h2)),
        "(k)"
    );

    // (l) the agent is itself a registered human; the helper says NULL.
    let sl = valid("l", h).await;
    fixture::make_human_operator(&pool, sl.agent).await;
    assert_eq!(
        binding(&pool, Some(sl.agent)).await,
        (
            Some("human_operator".to_string()),
            Some(sl.agent),
            Some(sl.agent)
        ),
        "(l)"
    );
    for (what, arg) in [("(l) direct", Some(sl.agent)), ("NULL argument", None)] {
        let op: Option<Uuid> =
            sqlx::query_scalar("SELECT public.epigraph_allowlisted_operator($1)")
                .bind(arg)
                .fetch_one(&pool)
                .await
                .expect("the helper, as the superuser");
        assert_eq!(op, None, "{what}");
    }

    // (m) the operator holds a link as an agent.
    let (h_m, _) = fixture::seed_human_operator(&pool, "m-human").await;
    let sm = valid("m", h_m).await;
    plant_link(&pool, h_m, h, g_h, false).await;
    assert_eq!(binding(&pool, Some(sm.agent)).await, UNBOUND, "(m)");

    // (n) a legacy link X -> S: S operates an agent.
    let sn = valid("n", h).await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "n-operated-x").await;
    plant_link(&pool, x, sn.agent, sn.group, true).await;
    assert_eq!(binding(&pool, Some(sn.agent)).await, UNBOUND, "(n)");

    // (o) a second ACTIVE client of the same agent; revoked, it no longer counts.
    let so = valid("o", h).await;
    let second = new_client(&pool, Some(so.agent), "service", "active", None).await;
    assert_eq!(binding(&pool, Some(so.agent)).await, UNBOUND, "(o)");
    set_status(&pool, second, "revoked").await;
    assert_eq!(
        binding(&pool, Some(so.agent)).await,
        allowlisted(h),
        "(o) a revoked second client does not count"
    );

    // (p) a registered system agent.
    let sp = valid("p", h).await;
    plant_system_agent(&pool, sp.agent).await;
    assert_eq!(binding(&pool, Some(sp.agent)).await, UNBOUND, "(p)");

    // (q) no system-agent table at all: the conjunct is skipped, not an error.
    sqlx::query("DROP TABLE public.system_agents CASCADE")
        .execute(&pool)
        .await
        .expect("drop the system-agent table");
    let fresh = PgPool::connect(&fixture::database_url_for(&pool).await)
        .await
        .expect("a fresh connection");
    assert_eq!(
        binding(&fresh, Some(calib.agent)).await,
        allowlisted(h),
        "(q) on a fresh connection"
    );
    assert_eq!(
        binding(&pool, Some(calib.agent)).await,
        allowlisted(h),
        "(q) on a pooled connection"
    );
}

// =====================================================================
// T4: the registry is maintenance-written, append-only and audited.
// =====================================================================

/// Every registry write path, in order: the application role writes nothing
/// (directly or through a definer) and reads everything it should; the
/// maintenance role allows through the audited definer, idempotently (also
/// under a concurrent retry) and with the binding it actually has; every
/// unmet precondition is refused; a direct write meets the same rules and
/// stamps its own provenance; the only change is the revoke, which is final;
/// no session deletes a row.
///
/// (A leftover app INSERT grant is killed by `app_role_table_lockdown.rs`'s
/// `NO_WRITE`, not here: the guard refuses the app role with the same 42501.)
///
/// Verified to fail: a guard
/// whose precondition checks are skipped on a direct maintenance write (the
/// human client row lands); `guard_update`'s column-tuple rule deleted (the
/// superuser rows land); the `refuse_delete` trigger removed (the superuser
/// DELETE lands); the allow definer reading before it locks (the concurrent
/// retry raises 55000); `effective_binding` hard-coded (the suspended
/// re-allow); the audit prefix changed to `operator.` (the event counts).
#[sqlx::test(migrations = "../../migrations")]
async fn the_allowlist_is_maintenance_written_append_only_and_audited(pool: PgPool) {
    let (h, g_h) = fixture::seed_human_operator(&pool, "human-h").await;
    let (h2, _) = fixture::seed_human_operator(&pool, "human-h2").await;
    let s = service(&pool, "service-s").await;

    // The application role: no write, no definer, but the reads.
    let app = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let mut codes = Vec::new();
        for stmt in [
            format!(
                "INSERT INTO author_binding_clients (client_id, operator_id, reason) \
                 VALUES ('{}', '{h}', 'x')",
                s.id
            ),
            "UPDATE author_binding_clients SET reason = 'x'".to_string(),
            "DELETE FROM author_binding_clients".to_string(),
            "TRUNCATE author_binding_clients".to_string(),
            format!(
                "SELECT * FROM public.epigraph_allow_author_binding_client('{}', '{h}', 'x')",
                s.id
            ),
            format!(
                "SELECT * FROM public.epigraph_revoke_author_binding_client('{}', 'x')",
                s.id
            ),
            format!("SELECT public.epigraph_allowlisted_operator('{}')", s.agent),
        ] {
            let r = sqlx::query(&stmt).execute(&mut *conn).await;
            codes.push((stmt, code_of(&r)));
        }
        let reads = sqlx::query(
            "SELECT (SELECT count(*) FROM author_binding_clients), \
                    public.epigraph_author_binding($1), public.epigraph_human_of($1, true)",
        )
        .bind(s.agent)
        .execute(&mut *conn)
        .await;
        (conn, (codes, reads))
    })
    .await;
    for (stmt, code) in &app.0 {
        assert_eq!(code.as_deref(), Some(INSUFFICIENT_PRIVILEGE), "app: {stmt}");
    }
    app.1
        .expect("the app role reads the table and the two binding functions");

    // Allow: a row, the pinned agent, the effective binding, one event.
    let a = allow(&pool, s.id, h, "the host writes for H")
        .await
        .expect("allow");
    assert_eq!(
        a,
        Allowed {
            allowed_now: true,
            agent_id: s.agent,
            operator_id: h,
            effective_binding: Some(CLIENT_ALLOWLIST.to_string()),
        }
    );
    assert_eq!(events(&pool, ALLOWED_EVENT, s.id).await, 1);
    let (ev_agent, ev_operator): (Option<Uuid>, Option<String>) = sqlx::query_as(
        "SELECT agent_id, details->>'operator_id' FROM security_events \
          WHERE event_type = $1 AND details->>'client_id' = $2::text",
    )
    .bind(ALLOWED_EVENT)
    .bind(s.id)
    .fetch_one(&pool)
    .await
    .expect("the event");
    assert_eq!(ev_agent, Some(s.agent));
    assert_eq!(ev_operator, Some(h.to_string()));

    // Again, same operator: idempotent, no event.
    let again = allow(&pool, s.id, h, "again").await.expect("again");
    assert!(!again.allowed_now);
    assert_eq!(again.effective_binding.as_deref(), Some(CLIENT_ALLOWLIST));
    assert_eq!(events(&pool, ALLOWED_EVENT, s.id).await, 1);

    // Same client, other operator.
    let r = allow(&pool, s.id, h2, "re-point").await;
    assert_refused(&r, OBJECT_STATE, "already allowed", "another operator");

    // A second client of the same agent (then revoked, restoring S).
    let c2 = new_client(&pool, Some(s.agent), "service", "active", None).await;
    let r = allow(&pool, c2, h, "second").await;
    assert_refused(&r, OBJECT_STATE, "another OAuth client", "a second client");
    set_status(&pool, c2, "revoked").await;

    // Every unmet precondition.
    let (hum, _) = fixture::seed_agent_with_group(&pool, "human-typed").await;
    let human_client = new_client(&pool, Some(hum), "human", "active", None).await;
    let pending = service(&pool, "pending").await;
    set_status(&pool, pending.id, "pending").await;
    let suspended = service(&pool, "suspended").await;
    set_status(&pool, suspended.id, "suspended").await;
    let revoked = service(&pool, "revoked").await;
    set_status(&pool, revoked.id, "revoked").await;
    let never_minted = new_client(&pool, None, "service", "active", None).await;
    let (l, _) = fixture::seed_agent_with_group(&pool, "linked").await;
    let linked = new_client(&pool, Some(l), "service", "active", None).await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, l, h)
            .await
            .expect("l -> h");
    }
    let (u, _) = fixture::seed_agent_with_group(&pool, "plain-operator").await;
    let (h3, _) = fixture::seed_human_operator(&pool, "linked-human").await;
    plant_link(&pool, h3, h, g_h, false).await;
    let fresh = service(&pool, "fresh").await;
    for (what, client, operator, fragment) in [
        ("a human client", human_client, h, "human client"),
        ("a pending client", pending.id, h, "not active"),
        ("a suspended client", suspended.id, h, "not active"),
        ("a revoked client", revoked.id, h, "not active"),
        ("a client with no agent", never_minted, h, "no agent yet"),
        ("a linked agent", linked, h, "holds an operator link"),
        (
            "a non-human operator",
            fresh.id,
            u,
            "not a registered human operator",
        ),
        ("a linked operator", fresh.id, h3, "itself linked"),
        (
            "agent = operator",
            fresh.id,
            fresh.agent,
            "not a registered human operator",
        ),
    ] {
        let r = allow(&pool, client, operator, "x").await;
        assert_refused(&r, OBJECT_STATE, fragment, what);
    }
    for (what, reason) in [("a blank reason", "  "), ("an empty reason", "")] {
        let r = allow(&pool, fresh.id, h, reason).await;
        assert_refused(&r, NULL_VALUE, "required", what);
    }
    let human_agent = service(&pool, "human-agent").await;
    fixture::make_human_operator(&pool, human_agent.agent).await;
    let r = allow(&pool, human_agent.id, h, "x").await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some(OBJECT_STATE),
        "a human agent: {r:?}"
    );

    // A direct maintenance INSERT meets the same guard and stamps provenance.
    let direct = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let refused = sqlx::query(
            "INSERT INTO author_binding_clients (client_id, operator_id, reason) \
             VALUES ($1, $2, 'direct')",
        )
        .bind(human_client)
        .bind(h)
        .execute(&mut *conn)
        .await;
        let landed = sqlx::query(
            "INSERT INTO author_binding_clients (client_id, operator_id, reason, added_by, \
                                                 added_at) \
             VALUES ($1, $2, 'direct', 'forged', '2001-01-01')",
        )
        .bind(fresh.id)
        .bind(h)
        .execute(&mut *conn)
        .await;
        (conn, (code_of(&refused), landed))
    })
    .await;
    assert_eq!(
        direct.0.as_deref(),
        Some(OBJECT_STATE),
        "a direct human-client row"
    );
    direct.1.expect("a direct, valid maintenance INSERT");
    let (added_by, recent, agent): (String, bool, Uuid) = sqlx::query_as(
        "SELECT added_by, added_at > now() - interval '1 hour', agent_id \
           FROM author_binding_clients WHERE client_id = $1",
    )
    .bind(fresh.id)
    .fetch_one(&pool)
    .await
    .expect("the direct row");
    assert_eq!(added_by, "epigraph_maintenance");
    assert!(recent, "added_at is stamped now(), not supplied");
    assert_eq!(agent, fresh.agent, "the agent is pinned by the guard");
    assert_eq!(
        events(&pool, ALLOWED_EVENT, fresh.id).await,
        1,
        "direct writes are audited"
    );

    // Maintenance holds no UPDATE on the non-revoke columns.
    for stmt in [
        "UPDATE author_binding_clients SET operator_id = operator_id WHERE client_id = $1",
        "UPDATE author_binding_clients SET reason = 'changed' WHERE client_id = $1",
    ] {
        let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r = sqlx::query(stmt).bind(fresh.id).execute(&mut *conn).await;
            (conn, r)
        })
        .await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "{stmt}"
        );
    }
    // The superuser bypasses the grants; the guard still refuses any change
    // but the revoke.
    for set in [
        format!("operator_id = '{h2}'"),
        "reason = 'changed'".to_string(),
        "added_by = 'changed'".to_string(),
    ] {
        let stmt = format!(
            "UPDATE author_binding_clients SET revoked_at = now(), revoked_by = 'x', \
                    revoked_reason = 'x', {set} WHERE client_id = $1"
        );
        let r = sqlx::query(&stmt).bind(fresh.id).execute(&pool).await;
        assert_refused(&r, OBJECT_STATE, "only ever revoked", &stmt);
    }
    // A revoke with no reason.
    let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query(
            "UPDATE author_binding_clients SET revoked_at = now() WHERE client_id = $1",
        )
        .bind(fresh.id)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert_refused(
        &r,
        OBJECT_STATE,
        "only ever revoked",
        "a revoke with no reason",
    );
    // A direct maintenance revoke with a forged `revoked_by`: stamped.
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query(
            "UPDATE author_binding_clients SET revoked_at = '2001-01-01', \
                    revoked_by = 'forged', revoked_reason = 'direct revoke' \
              WHERE client_id = $1",
        )
        .bind(fresh.id)
        .execute(&mut *conn)
        .await
        .expect("a direct maintenance revoke");
        (conn, ())
    })
    .await;
    let (revoked_by, recent): (String, bool) = sqlx::query_as(
        "SELECT revoked_by, revoked_at > now() - interval '1 hour' \
           FROM author_binding_clients WHERE client_id = $1",
    )
    .bind(fresh.id)
    .fetch_one(&pool)
    .await
    .expect("revoked row");
    assert_eq!(revoked_by, "epigraph_maintenance");
    assert!(recent);
    assert_eq!(events(&pool, REVOKED_EVENT, fresh.id).await, 1);

    // The definer revoke ends the binding; it is final.
    assert!(revoke(&pool, s.id, "incident").await.expect("revoke"));
    assert_eq!(events(&pool, REVOKED_EVENT, s.id).await, 1);
    assert_eq!(binding(&pool, Some(s.agent)).await, UNBOUND);
    assert!(!revoke(&pool, s.id, "again").await.expect("revoke again"));
    assert_eq!(events(&pool, REVOKED_EVENT, s.id).await, 1);
    let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query(
            "UPDATE author_binding_clients SET revoked_reason = 'rewritten' WHERE client_id = $1",
        )
        .bind(s.id)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert_refused(
        &r,
        OBJECT_STATE,
        "revoke is final",
        "an UPDATE of a revoked row",
    );
    let r = allow(&pool, s.id, h, "revive").await;
    assert_refused(
        &r,
        OBJECT_STATE,
        "not revived",
        "re-allowing a revoked client",
    );
    for (what, client, reason) in [
        ("NULL client", None, "x"),
        ("blank reason", Some(s.id), " "),
    ] {
        let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r =
                sqlx::query("SELECT * FROM public.epigraph_revoke_author_binding_client($1, $2)")
                    .bind(client)
                    .bind(reason)
                    .execute(&mut *conn)
                    .await;
            (conn, r)
        })
        .await;
        assert_eq!(code_of(&r).as_deref(), Some(NULL_VALUE), "revoke, {what}");
    }

    // No session deletes a row.
    let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query("DELETE FROM author_binding_clients WHERE client_id = $1")
            .bind(s.id)
            .execute(&mut *conn)
            .await;
        (conn, r)
    })
    .await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "maintenance DELETE"
    );
    let r = sqlx::query("DELETE FROM author_binding_clients WHERE client_id = $1")
        .bind(s.id)
        .execute(&pool)
        .await;
    assert_refused(&r, OBJECT_STATE, "never deleted", "a superuser DELETE");
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM author_binding_clients WHERE client_id = $1")
            .bind(s.id)
            .fetch_one(&pool)
            .await
            .expect("rows");
    assert_eq!(rows, 1, "the row survives");

    // 123 regression guard: an application session forges no `platform.` event.
    let forged = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r = sqlx::query(
            "INSERT INTO security_events (event_type, agent_id, success, details) \
             VALUES ($1, NULL, true, '{}'::jsonb)",
        )
        .bind(ALLOWED_EVENT)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert!(forged.is_err(), "an app-forged platform event: {forged:?}");

    // A concurrent retry: the second caller waits on the lock, then finds the row.
    let racer = service(&pool, "racer").await;
    let mut first = pool.acquire().await.expect("acquire");
    sqlx::query("SET SESSION AUTHORIZATION epigraph_maintenance")
        .execute(&mut *first)
        .await
        .expect("first as maintenance");
    sqlx::query("BEGIN")
        .execute(&mut *first)
        .await
        .expect("begin");
    let one = allow_on(&mut first, racer.id, h, "race")
        .await
        .expect("first allow");
    assert!(one.allowed_now);
    let second = {
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut conn = pool.acquire().await.expect("acquire");
            sqlx::query("SET SESSION AUTHORIZATION epigraph_maintenance")
                .execute(&mut *conn)
                .await
                .expect("second as maintenance");
            let r = allow_on(&mut conn, racer.id, h, "race").await;
            sqlx::query("RESET SESSION AUTHORIZATION")
                .execute(&mut *conn)
                .await
                .expect("reset");
            r
        })
    };
    let mut waited = false;
    for _ in 0..200 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_locks \
              WHERE locktype = 'advisory' AND NOT granted \
                AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .fetch_one(&pool)
        .await
        .expect("pg_locks");
        if waiting > 0 {
            waited = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(waited, "the second caller blocks on the advisory lock");
    sqlx::query("COMMIT")
        .execute(&mut *first)
        .await
        .expect("commit");
    sqlx::query("RESET SESSION AUTHORIZATION")
        .execute(&mut *first)
        .await
        .expect("reset");
    drop(first);
    let two = second
        .await
        .expect("join")
        .expect("the retry is not an error");
    assert!(!two.allowed_now, "the retry finds the committed row");
    assert_eq!(events(&pool, ALLOWED_EVENT, racer.id).await, 1);

    // A re-allow of a dead allowance reports the binding it actually has.
    set_status(&pool, racer.id, "suspended").await;
    let dead = allow(&pool, racer.id, h, "again").await.expect("re-allow");
    assert!(!dead.allowed_now);
    assert_eq!(
        dead.effective_binding, None,
        "a suspended client is not bound"
    );
}

/// A direct maintenance INSERT that names an agent other than the client's
/// own is refused by the insert guard, and nothing is stored (D-4: the row
/// pins the client's agent; the guard's other checks must never run against
/// a supplied agent).
///
/// Verified to fail: the guard's pinned-agent check removed (the row lands).
#[sqlx::test(migrations = "../../migrations")]
async fn a_direct_insert_naming_another_agent_is_refused(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human-h").await;
    let s = service(&pool, "service-s").await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "other").await;
    let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query(
            "INSERT INTO author_binding_clients (client_id, agent_id, operator_id, reason) \
             VALUES ($1, $2, $3, 'direct')",
        )
        .bind(s.id)
        .bind(other)
        .bind(h)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert_refused(&r, OBJECT_STATE, "agent is", "a mismatched pinned agent");
    assert_eq!(
        (
            events(&pool, ALLOWED_EVENT, s.id).await,
            binding(&pool, Some(s.agent)).await
        ),
        (0, UNBOUND),
        "nothing stored, nothing audited"
    );
}

/// A direct maintenance INSERT with a blank reason is refused by the insert
/// guard itself (the definer's own reason check never runs on this path).
///
/// Verified to fail: the guard's reason check removed (the row lands).
#[sqlx::test(migrations = "../../migrations")]
async fn a_direct_insert_with_a_blank_reason_is_refused(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human-h").await;
    let s = service(&pool, "service-s").await;
    let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query(
            "INSERT INTO author_binding_clients (client_id, operator_id, reason) \
             VALUES ($1, $2, '   ')",
        )
        .bind(s.id)
        .bind(h)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert_refused(
        &r,
        NULL_VALUE,
        "reason is required",
        "a blank direct reason",
    );
    assert_eq!(binding(&pool, Some(s.agent)).await, UNBOUND);
}

/// A direct maintenance INSERT of an already-revoked row is refused: an
/// allowance is recorded live and revoked only through the revoke path, so a
/// dead row (which would also block the client from ever being allowed) is
/// never stored with an `..._allowed` audit row.
///
/// Verified to fail: the guard's live-on-insert check removed (the row lands).
#[sqlx::test(migrations = "../../migrations")]
async fn a_direct_insert_of_a_revoked_row_is_refused(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human-h").await;
    let s = service(&pool, "service-s").await;
    let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query(
            "INSERT INTO author_binding_clients (client_id, operator_id, reason, revoked_at, \
                                                 revoked_by, revoked_reason) \
             VALUES ($1, $2, 'direct', now(), 'x', 'x')",
        )
        .bind(s.id)
        .bind(h)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert_refused(
        &r,
        OBJECT_STATE,
        "recorded live",
        "a pre-revoked direct row",
    );
    assert_eq!(
        events(&pool, ALLOWED_EVENT, s.id).await,
        0,
        "nothing audited"
    );
    allow(&pool, s.id, h, "allowed after the refused direct row")
        .await
        .expect("the client is still allowable");
}

// =====================================================================
// T5 / T10: links and the allowlist.
// =====================================================================

/// A new operator link of an agent with a live allowance whose client is not
/// revoked is refused, by name, and records nothing; revoking the allowance
/// lets the link through.
///
/// Verified to fail: `CREATE TRIGGER operator_links_refuse_allowlisted_agent`
/// removed -> the link lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_link_is_refused_for_an_allowlisted_agent_until_the_allowance_is_revoked(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human-h").await;
    let s = service(&pool, "service-s").await;
    allow(&pool, s.id, h, "test").await.expect("allow");

    for definer in ["epigraph_link_operator", "epigraph_link_retired_agent"] {
        let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r = sqlx::query(&format!("SELECT * FROM public.{definer}($1, $2)"))
                .bind(s.agent)
                .bind(h)
                .execute(&mut *conn)
                .await;
            (conn, r)
        })
        .await;
        assert_refused(&r, OBJECT_STATE, LINK_GUARD_FRAGMENT, definer);
        let text = r.expect_err("refused").to_string();
        assert!(text.contains(&s.id.to_string()), "names the client: {text}");
        let (links, edges): (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM operator_links WHERE agent_id = $1), \
                    (SELECT count(*) FROM edges \
                      WHERE source_id = $1 AND relationship = 'OPERATED_BY')",
        )
        .bind(s.agent)
        .fetch_one(&pool)
        .await
        .expect("counts");
        assert_eq!((links, edges), (0, 0), "{definer} recorded nothing");
    }

    assert!(revoke(&pool, s.id, "linking instead")
        .await
        .expect("revoke"));
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_link_operator($1, $2)")
            .bind(s.agent)
            .bind(h)
            .execute(&mut *conn)
            .await
            .expect("linked once the allowance is revoked");
        (conn, ())
    })
    .await;
    assert_eq!(
        binding(&pool, Some(s.agent)).await,
        (Some("live_link".to_string()), Some(h), Some(h))
    );
}

/// The link guard's "unmet" column: a live allowance whose client is
/// SUSPENDED (not revoked) still refuses a new link. Suspending is the
/// incident step that comes before a revoke; a link landing then would make
/// the agent stdio-only, the side effect the guard exists to refuse.
///
/// Verified to fail: the guard narrowed to `c.status = 'active'` (the link
/// lands).
#[sqlx::test(migrations = "../../migrations")]
async fn a_suspended_allowlisted_client_still_refuses_a_link(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human-h").await;
    let s = service(&pool, "service-s").await;
    allow(&pool, s.id, h, "test").await.expect("allow");
    set_status(&pool, s.id, "suspended").await;
    let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query("SELECT * FROM public.epigraph_link_operator($1, $2)")
            .bind(s.agent)
            .bind(h)
            .execute(&mut *conn)
            .await;
        (conn, r)
    })
    .await;
    assert_refused(
        &r,
        OBJECT_STATE,
        LINK_GUARD_FRAGMENT,
        "suspended client, live allowance",
    );
    let links: i64 = sqlx::query_scalar("SELECT count(*) FROM operator_links WHERE agent_id = $1")
        .bind(s.agent)
        .fetch_one(&pool)
        .await
        .expect("links");
    assert_eq!(links, 0, "no link recorded");
}

/// An exact re-link (the agent already holds its link row) is discarded by
/// the caller's `ON CONFLICT DO NOTHING`, never refused by the link guard,
/// even when a live allowance for the agent exists (planted: the state a
/// concurrent allow and link can reach under REPEATABLE READ). A stdio
/// process re-links at every start, so a refusal here would be a fatal
/// startup.
///
/// Verified to fail: the guard's existing-link early return removed (the
/// re-link raises 55000).
#[sqlx::test(migrations = "../../migrations")]
async fn an_exact_relink_is_never_refused(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human-h").await;
    let (l, _) = fixture::seed_agent_with_group(&pool, "linked").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, l, h)
            .await
            .expect("first link");
    }
    let c = new_client(&pool, Some(l), "service", "active", None).await;
    plant(&pool, c, l, h, false).await;
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, l, h)
        .await
        .expect("an exact re-link is discarded, not refused");
    drop(conn);
    assert_eq!(
        binding(&pool, Some(l)).await,
        (Some("live_link".to_string()), Some(h), Some(h)),
        "the link decides"
    );
}

/// The legacy-author tie never meets the link guard: an allowlisted agent
/// whose client is REVOKED (its allowance still live) is an ordinary
/// candidate and is linked, and the link then decides; one whose client is
/// not revoked is skipped as an OAuth principal. One audit row; the tie
/// completes.
///
/// Verified to fail: the link guard keyed on the allowance row alone (no
/// `c.status <> 'revoked'`) -> the tie raises 55000 and writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_client_with_a_live_allowance_does_not_wedge_the_legacy_tie(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human-h").await;
    let (h2, _) = fixture::seed_human_operator(&pool, "human-h2").await;
    let s = service(&pool, "revoked-client").await;
    let live = service(&pool, "live-client").await;
    allow(&pool, s.id, h, "test").await.expect("allow s");
    allow(&pool, live.id, h, "test").await.expect("allow live");
    insert_claim(&pool, s.agent, s.group)
        .await
        .expect("s authors");
    insert_claim(&pool, live.agent, live.group)
        .await
        .expect("live authors");
    set_status(&pool, s.id, "revoked").await;

    let outcomes: Vec<(Uuid, String)> =
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r = sqlx::query_as(
                "SELECT agent_id, outcome FROM public.epigraph_link_legacy_authors($1, '{}', NULL)",
            )
            .bind(h2)
            .fetch_all(&mut *conn)
            .await
            .expect("the legacy tie completes");
            (conn, r)
        })
        .await;
    let outcome = |a: Uuid| {
        outcomes
            .iter()
            .find(|(x, _)| *x == a)
            .map(|(_, o)| o.clone())
    };
    assert_eq!(outcome(s.agent).as_deref(), Some("linked"), "{outcomes:?}");
    assert_eq!(
        outcome(live.agent).as_deref(),
        Some("skipped:oauth_principal"),
        "CALIBRATION: {outcomes:?}"
    );
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'operator.legacy_authors_linked'",
    )
    .fetch_one(&pool)
    .await
    .expect("audit");
    assert_eq!(audits, 1);
    let b = binding(&pool, Some(s.agent)).await;
    assert_eq!(b.0, None, "a retired link and a revoked client: unbound");
    assert_eq!(b.2, Some(h2), "the link wins");
}

// =====================================================================
// T6 / T7 / T11 / T12 / T13 / T14.
// =====================================================================

/// Unarmed, an allowance changes no write: both shapes are admitted before
/// and after it. Then armed, the as-itself write is refused (the instrument
/// can fail).
///
/// Should fail if a re-body made any check run unarmed (not measured: no 149
/// object reads the arming state; the armed calibration at the end shows the
/// instrument can fail).
#[sqlx::test(migrations = "../../migrations")]
async fn an_unarmed_database_admits_the_same_writes_with_or_without_an_allowance(pool: PgPool) {
    let (h, g_h) = fixture::seed_human_operator(&pool, "human-h").await;
    let (l, _) = fixture::seed_agent_with_group(&pool, "h-agent-l").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, l, h)
            .await
            .expect("l -> h");
    }
    let s = service(&pool, "service-s").await;
    for state in ["before", "after"] {
        if state == "after" {
            allow(&pool, s.id, h, "test").await.expect("allow");
        }
        write_as(&pool, s.agent, &[s.group], s.agent, s.group)
            .await
            .unwrap_or_else(|e| panic!("{state}: as itself: {e}"));
        write_as(&pool, s.agent, &[g_h], l, g_h)
            .await
            .unwrap_or_else(|e| panic!("{state}: the host shape: {e}"));
    }
    arm(&pool).await;
    let r = write_as(&pool, s.agent, &[s.group], s.agent, s.group).await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some(OPL02),
        "CALIBRATION, armed: {r:?}"
    );
}

/// The valve column of the behaviour matrix: with the session's valve open,
/// an allowlisted writer is scoped to its operator. Its as-itself write into
/// its own group is admitted before the allowance and refused after it (a
/// documented regression for a valve user), and the host shape is refused
/// before it and admitted after it.
#[sqlx::test(migrations = "../../migrations")]
async fn under_the_valve_an_allowlisted_writer_is_scoped_to_its_operator(pool: PgPool) {
    let (h, g_h) = fixture::seed_human_operator(&pool, "human-h").await;
    let (l, _) = fixture::seed_agent_with_group(&pool, "h-agent-l").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, l, h)
            .await
            .expect("l -> h");
    }
    let s = service(&pool, "service-s").await;
    arm(&pool).await;

    valve_write(&pool, s.agent, &[s.group], s.agent, s.group)
        .await
        .expect("before: the valve admits an unbound author as itself");
    let r = valve_write(&pool, s.agent, &[g_h], l, g_h).await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some(OPL02),
        "before, host shape: {r:?}"
    );

    allow(&pool, s.id, h, "test").await.expect("allow");
    let r = valve_write(&pool, s.agent, &[s.group], s.agent, s.group).await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some(OPL02),
        "after, as itself: {r:?}"
    );
    valve_write(&pool, s.agent, &[g_h], l, g_h)
        .await
        .expect("after: the host shape");
}

/// An allowlisted agent that authors AS ITSELF is not re-homed: the default
/// declaration is still its own personal group (the early check is quiet),
/// and once armed that write is refused OPL02, because its operator does not
/// write that group. Every "author as itself" path resolves through this one
/// function.
///
/// Should fail if an allowlisted author were re-homed into its operator's
/// group (the declaration would be G_H); not measured, as no such re-home
/// exists to mutate.
#[sqlx::test(migrations = "../../migrations")]
async fn an_allowlisted_author_as_itself_is_not_rehomed(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human-h").await;
    let s = service(&pool, "service-s").await;
    allow(&pool, s.id, h, "test").await.expect("allow");

    let decl = |pool: PgPool| async move {
        as_app_stamped(&pool, s.agent, &[s.group], |mut conn| async move {
            let r = epigraph_db::ClaimRepository::default_decl_for_author(&mut conn, s.agent).await;
            (conn, r)
        })
        .await
    };
    // Unarmed control.
    let d = decl(pool.clone()).await.expect("unarmed decl");
    assert_eq!(d.owner_group_bind(), Some(s.group));
    write_as(&pool, s.agent, &[s.group], s.agent, s.group)
        .await
        .expect("unarmed, as itself");

    arm(&pool).await;
    let d = decl(pool.clone())
        .await
        .expect("armed decl: the early check is quiet");
    assert_eq!(
        d.owner_group_bind(),
        Some(s.group),
        "G_S, not its operator's group"
    );
    let r = write_as(&pool, s.agent, &[s.group], s.agent, s.group).await;
    assert_eq!(code_of(&r).as_deref(), Some(OPL02), "{r:?}");
}

/// The allowance names ONE client's agent: allowing a client whose agent has
/// another non-revoked client is refused, and a second client created later
/// ends the binding until it is revoked.
///
/// Verified to fail: the guard's other-client check removed (i lands). The
/// read's other-client conjunct removed is measured by T3 (o); (ii) should
/// fail the same way.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_client_of_the_same_agent_is_refused_and_unbinds(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human-h").await;
    // (i)
    let s = service(&pool, "two-clients").await;
    new_client(&pool, Some(s.agent), "service", "active", None).await;
    let r = allow(&pool, s.id, h, "test").await;
    assert_refused(&r, OBJECT_STATE, "another OAuth client", "(i)");
    // (ii)
    let t = service(&pool, "one-client").await;
    allow(&pool, t.id, h, "test").await.expect("allow");
    let later = new_client(
        &pool,
        Some(t.agent),
        "agent",
        "active",
        Some(human_client_of(&pool, h).await),
    )
    .await;
    assert_eq!(binding(&pool, Some(t.agent)).await, UNBOUND, "(ii)");
    // (iii)
    set_status(&pool, later, "revoked").await;
    assert_eq!(binding(&pool, Some(t.agent)).await, allowlisted(h), "(iii)");
}

/// The attribution surface the allowance opens, pinned row by row (armed):
///
/// 1. S, holding a write membership in another human's group, writes a claim
///    by its operator's agent there: OPL02 (writer scope).
/// 2. S authors as its operator, in the operator's group: admitted (the same
///    parity a live-linked agent has).
/// 3. H's other agent names S as the author: OPL01 before, admitted after.
/// 4. Another human's agent names S: OPL02.
/// 5. S supersedes a retired-linked identity of H's claim: admitted.
/// 6. S names that retired identity on a fresh claim: OPL01.
#[sqlx::test(migrations = "../../migrations")]
async fn the_new_attribution_surface_is_pinned(pool: PgPool) {
    let (h, g_h) = fixture::seed_human_operator(&pool, "human-h").await;
    let (b, g_b) = fixture::seed_human_operator(&pool, "human-b").await;
    let (l, _) = fixture::seed_agent_with_group(&pool, "h-agent-l").await;
    let (l_b, _) = fixture::seed_agent_with_group(&pool, "b-agent-lb").await;
    let (r, _) = fixture::seed_agent_with_group(&pool, "h-retired-r").await;
    let s = service(&pool, "service-s").await;
    let r_claim = insert_claim(&pool, r, g_h).await.expect("R's claim");
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, l, h)
            .await
            .expect("l -> h");
        AgentRepository::link_operator(&mut conn, l_b, b)
            .await
            .expect("l_b -> b");
        AgentRepository::link_retired_agent(&mut conn, r, h)
            .await
            .expect("r -> h, retired");
    }
    // S holds a writer row in B's group (an enrolment B made before arming).
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(g_b)
    .bind(s.agent)
    .execute(&pool)
    .await
    .expect("S writes in B's group");
    arm(&pool).await;

    let before = write_as(&pool, l, &[g_h], s.agent, g_h).await;
    assert_eq!(
        code_of(&before).as_deref(),
        Some(OPL01),
        "3, before: {before:?}"
    );
    allow(&pool, s.id, h, "test").await.expect("allow");

    let r1 = write_as(&pool, s.agent, &[g_b], l, g_b).await;
    assert_eq!(code_of(&r1).as_deref(), Some(OPL02), "1: {r1:?}");
    write_as(&pool, s.agent, &[g_h], h, g_h)
        .await
        .expect("2: S authors as its operator");
    write_as(&pool, l, &[g_h], s.agent, g_h)
        .await
        .expect("3: H's agent names S");
    let r4 = write_as(&pool, l_b, &[g_b], s.agent, g_b).await;
    assert_eq!(code_of(&r4).as_deref(), Some(OPL02), "4: {r4:?}");
    assert_eq!(binding(&pool, Some(r)).await.2, Some(h), "R belongs to H");
    as_app_stamped(&pool, s.agent, &[g_h], |mut conn| async move {
        let res = {
            let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
            let res = epigraph_db::ClaimRepository::supersede_act_conn(
                &mut tx,
                epigraph_core::ClaimId::from_uuid(r_claim),
                "a revision of R's claim",
                epigraph_core::TruthValue::new(0.6).expect("truth"),
                "author binding allowlist probe",
            )
            .await;
            if res.is_ok() {
                tx.commit().await.expect("commit");
            }
            res
        };
        (conn, res)
    })
    .await
    .expect("5: S supersedes its human's retired identity's claim");
    let r6 = write_as(&pool, s.agent, &[g_h], r, g_h).await;
    assert_eq!(code_of(&r6).as_deref(), Some(OPL01), "6: {r6:?}");
}

/// An agent that operates others, or that is a registered system agent, is
/// never allowlisted.
///
/// Verified to fail: either guard check removed.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operator_of_agents_and_a_system_agent_are_never_allowlisted(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human-h").await;
    // (i) a legacy link X -> S.
    let s = service(&pool, "operates-x").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "x").await;
    plant_link(&pool, x, s.agent, s.group, true).await;
    let r = allow(&pool, s.id, h, "test").await;
    assert_refused(&r, OBJECT_STATE, "operates other agents", "(i)");
    // (ii) a registered system agent.
    let t = service(&pool, "system").await;
    plant_system_agent(&pool, t.agent).await;
    let r = allow(&pool, t.id, h, "test").await;
    assert_refused(&r, OBJECT_STATE, "registered system agent", "(ii)");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM author_binding_clients")
        .fetch_one(&pool)
        .await
        .expect("rows");
    assert_eq!(rows, 0);
}

// =====================================================================
// T8 / T9: the rollback and the registers.
// =====================================================================

/// The catalog facts 149 could leave behind, by name: relations, functions
/// (body and owner), policies, triggers and constraints in `public` (the
/// `admin_scope_enforcement.rs::catalog` query), plus the ACL of the two
/// functions 149 re-bodies, because `CREATE OR REPLACE` keeps an ACL that an
/// undo could leave different.
async fn catalog(pool: &PgPool) -> std::collections::BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || md5(p.prosrc) || ' ' || p.proowner::regrole::text \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'acl ' || p.proname || ' ' || coalesce(p.proacl::text, '') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
            AND p.proname IN ('epigraph_author_binding', 'epigraph_human_of') \
         UNION ALL \
         SELECT 'pol ' || c.relname || '.' || pol.polname \
           FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'trg ' || c.relname || '.' || t.tgname \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'con ' || c.relname || '.' || k.conname \
           FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
          WHERE c.relnamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

fn read_repo(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// `docs/runbooks/149-undo.sql`, applied twice to a database that went
/// pre-149 -> 149 and allowed one client, returns its catalog (relations,
/// function bodies, owners and the re-bodied functions' ACLs, policies,
/// triggers, constraints) to the pre-149 one, so the two binding reads are
/// 122's again byte for byte, and records the removal as exactly one
/// `platform.author_binding_allowlist_dropped` event naming the one live
/// allowance it ended.
///
/// Verified to fail: a non-122 body of `epigraph_human_of` restored (the
/// catalog differs). Dropping the helper BEFORE restoring the bodies would not
/// error (a SQL function body records no dependency), so the undo restores
/// the bodies first by construction, not because this test could catch it.
#[sqlx::test(migrations = false)]
async fn the_149_rollback_returns_the_catalog_and_records_the_dropped_allowances(pool: PgPool) {
    migrate(&pool, &up_to_below(149)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &MIGRATOR).await;
    assert_ne!(
        catalog(&pool).await,
        before,
        "CALIBRATION: 149 changed the catalog"
    );
    let (h, _) = fixture::seed_human_operator(&pool, "human-h").await;
    let s = service(&pool, "service-s").await;
    allow(&pool, s.id, h, "test").await.expect("allow");

    let undo = read_repo("docs/runbooks/149-undo.sql");
    for run in 1..=2 {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the undo script applies (run {run}): {e}"));
    }
    let after = catalog(&pool).await;
    let left: Vec<&String> = after.difference(&before).collect();
    let lost: Vec<&String> = before.difference(&after).collect();
    assert!(
        left.is_empty() && lost.is_empty(),
        "the catalog is not pre-149's after the undo; left behind: {left:?}; lost: {lost:?}"
    );
    let dropped: Vec<(Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT (details->>'live_allowances')::bigint, details->>'reason' FROM security_events \
          WHERE event_type = 'platform.author_binding_allowlist_dropped'",
    )
    .fetch_all(&pool)
    .await
    .expect("events");
    assert_eq!(
        dropped,
        vec![(Some(1), Some("149-undo".to_string()))],
        "one dropped event across two runs, naming the one live allowance"
    );
}

/// Every function 149 creates is a SECURITY DEFINER; each new one is on
/// `epigraph-tenancy-backfill verify`'s ownership list at 149 (the two
/// re-bodied reads stay registered at 122); each non-app definer is on its
/// grant register as not app-callable; and `docs/runbooks/149-undo.sql`
/// restores the two re-bodied reads and drops everything else.
///
/// Verified to fail: a `(..., 149)` register entry removed -> named here.
#[test]
fn every_149_object_is_registered() {
    let migration = read_repo("migrations/149_author_binding_allowlist.sql");
    let backfill = read_repo("crates/epigraph-cli/src/bin/tenancy_backfill.rs");
    let undo = read_repo("docs/runbooks/149-undo.sql");

    let marker = "CREATE OR REPLACE FUNCTION public.";
    let mut definers = Vec::new();
    let mut all = Vec::new();
    let mut rest = migration.as_str();
    while let Some(i) = rest.find(marker) {
        let after = &rest[i + marker.len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let body_end = after.find("$$;").unwrap_or(after.len());
        let header_end = after.find(" AS $$").unwrap_or(body_end);
        if after[..header_end].contains("SECURITY DEFINER") {
            definers.push(name.clone());
        }
        all.push(name);
        rest = &after[body_end..];
    }
    definers.sort();
    all.sort();
    assert_eq!(
        definers.len(),
        10,
        "CALIBRATION: 149 creates or re-bodies 10 SECURITY DEFINER functions: {definers:?}"
    );
    assert_eq!(definers, all, "every function 149 creates is a definer");

    let rebodied = ["epigraph_author_binding", "epigraph_human_of"];
    let new: Vec<&String> = all
        .iter()
        .filter(|n| !rebodied.contains(&n.as_str()))
        .collect();
    assert_eq!(new.len(), 8, "8 new functions: {new:?}");
    let missing: Vec<&&String> = new
        .iter()
        .filter(|n| !backfill.contains(&format!("(\"{n}\", 149)")))
        .collect();
    assert!(
        missing.is_empty(),
        "149 definers missing from tenancy_backfill.rs's ownership list at 149: {missing:?}"
    );
    for n in rebodied {
        assert!(
            backfill.contains(&format!("(\"{n}\", 122)")),
            "{n} must stay registered at 122"
        );
        assert!(
            undo.contains(&format!("CREATE OR REPLACE FUNCTION public.{n}(")),
            "149-undo.sql must restore {n}"
        );
    }
    for callable in [
        "public.epigraph_allow_author_binding_client(uuid, uuid, text)",
        "public.epigraph_revoke_author_binding_client(uuid, text)",
        "public.epigraph_allowlisted_operator(uuid)",
    ] {
        assert!(
            backfill.contains(&format!("\"{callable}\",\n            false,")),
            "{callable} must be on tenancy_backfill.rs's grant register as not app-callable"
        );
    }
    let undropped: Vec<&&String> = new
        .iter()
        .filter(|n| !undo.contains(&format!("DROP FUNCTION IF EXISTS public.{n}(")))
        .collect();
    assert!(
        undropped.is_empty(),
        "149-undo.sql does not drop: {undropped:?}"
    );
    assert!(
        undo.contains("DROP TABLE IF EXISTS public.author_binding_clients;"),
        "149-undo.sql does not drop the registry"
    );
}
