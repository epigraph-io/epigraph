//! Migration 165: group membership DERIVED from time-windowed role
//! assignments.
//!
//! A maintenance-only, append-only `group_role_bindings` row binds a
//! NON-ELEVATING platform role to a group at `reader` or `writer` (never
//! `admin`). While a binding is live:
//!
//! * a registered human holding a LIVE assignment of the role (123's window:
//!   `valid_from <= t < valid_to`, not ended) is a member of the group;
//! * when the binding says `include_agents`, so is every agent REGISTERED TO
//!   such a human: an ACTING live link (107's `epigraph_operator_actor`) or a
//!   live 149 client allowance. A retired link, an agent whose acting row was
//!   revoked, and an agent of a revoked or suspended human never derive.
//!
//! Membership is COMPUTED when the viewer is resolved, never written:
//! `epigraph_live_memberships` (077, re-stated by 164) is the direct rows
//! UNION the derived rows, and 123's claims-path writer scope (OPL02) asks the
//! effective question for the writing human. Membership-door checks (122's
//! `epigraph_operator_writes_group`, which the team-group verbs and the
//! application roster path call) stay DIRECT-ONLY, so an explicit row can
//! never be given on the strength of a derived one and outlive the window.
//!
//! What is pinned, each refusal next to the positive control that shows the
//! same shape succeeds when the refused condition is absent:
//!
//! * the window: nothing before `valid_from`; a lapse at `valid_to` with no
//!   job and no membership row written; an end mid-window lapses at once;
//! * link states, human status, the allowance arm, `include_agents`, a
//!   reader-only binding;
//! * armed, a write stamped (forged) with the group is refused OPL02 for a
//!   principal outside the window, and an honest write inside it lands;
//! * the door stays direct-only (GRP03 from the verbs, OPL02 from the door);
//! * the new helpers are maintenance-owned definers the application role
//!   cannot execute (no roster oracle), and `epigraph_live_memberships` keeps
//!   its signature and its application grant;
//! * no binding rides on an elevating or audit-reading role, none confers
//!   admin, and only a maintenance session writes the table, append-only.
//!
//! Every write that matters runs on a session whose `session_user` is the
//! deployed role (`SET SESSION AUTHORIZATION`), never on the harness
//! superuser, so grants and row security are what is measured.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{AgentRepository, Viewer};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

/// A synthetic, non-elevating role key used throughout.
const ROLE: &str = "role:team-member";

const NOT_BINDABLE_ROLE: &str = "GRB01";
const NOT_BINDABLE_GROUP: &str = "GRB02";
const ROLE_KEY_TAKEN: &str = "GRB03";
const OPERATOR_SCOPE: &str = "GRP03";
const OPL02: &str = "OPL02";

/// The words of each OPL02 refusal, so the check that refused is the one named.
const HUMAN_SCOPE: &str = "a human writes only where it writes";
const AGENT_SCOPE: &str = "writes only where its own operator writes";

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

fn code_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> Option<String> {
    r.as_ref().err().and_then(sqlstate)
}

fn message_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> String {
    r.as_ref()
        .err()
        .and_then(|e| e.as_database_error().map(|d| d.message().to_string()))
        .unwrap_or_default()
}

/// `Err` with SQLSTATE `code` whose message carries `fragment`.
fn assert_refused<T: std::fmt::Debug>(
    r: &Result<T, sqlx::Error>,
    code: &str,
    fragment: &str,
    what: &str,
) {
    assert_eq!(code_of(r).as_deref(), Some(code), "{what}: {r:?}");
    let msg = message_of(r);
    assert!(
        msg.contains(fragment),
        "{what}: expected the refusal to say {fragment:?}, got {msg:?}"
    );
}

/// A connection whose `session_user` is `epigraph_maintenance`.
async fn maint(pool: &PgPool) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    use sqlx::Executor;
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_maintenance")
        .await
        .expect("downgrade to the maintenance role");
    conn
}

async fn reset(mut conn: sqlx::pool::PoolConnection<sqlx::Postgres>) {
    use sqlx::Executor;
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset session authorization");
}

/// A registered human operator with its personal group.
async fn human(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    fixture::seed_human_operator(pool, label).await
}

/// An agent LIVE-linked to `operator` through 107's real link (which writes
/// its acting row in the operator's personal group).
async fn operated(pool: &PgPool, operator: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let out = AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link the agent");
    assert!(out.link_live, "PREMISE: a live link: {out:?}");
    agent
}

/// An agent with a RETIRED link to `operator`.
async fn retired(pool: &PgPool, operator: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_retired_agent(&mut conn, agent, operator)
        .await
        .expect("retire-link the agent");
    agent
}

/// A fresh agent bound to `operator` by a 149 client ALLOWANCE. Returns
/// `(agent, client)`.
async fn allowance_bound(pool: &PgPool, operator: Uuid, label: &str) -> (Uuid, Uuid) {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'role membership allowance fixture', 'service', ARRAY['claims:write'], \
                 'active', $2, 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("role-membership-allowance-{}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("service client");
    let mut c = maint(pool).await;
    sqlx::query("SELECT allowed_now FROM public.epigraph_allow_author_binding_client($1, $2, $3)")
        .bind(client)
        .bind(operator)
        .bind("role membership test")
        .fetch_one(&mut *c)
        .await
        .expect("allow the client for the operator");
    reset(c).await;
    (agent, client)
}

/// A keyless team group made by migration 164's verb, administered by `admin`.
async fn team_group(pool: &PgPool, name: &str, admin: Uuid) -> Uuid {
    let mut c = maint(pool).await;
    let g: Uuid = sqlx::query_scalar("SELECT public.epigraph_create_team_group($1, $2, $3)")
        .bind(name)
        .bind(admin)
        .bind("role membership test")
        .fetch_one(&mut *c)
        .await
        .expect("create the team group");
    reset(c).await;
    g
}

/// `epigraph_define_group_role` on a maintenance session: a new catalog role
/// (non-elevating, no audit read) bound to `group`. Returns the binding id.
async fn define(
    pool: &PgPool,
    key: &str,
    group: Uuid,
    member_role: &str,
    include_agents: bool,
) -> Result<Uuid, sqlx::Error> {
    let mut c = maint(pool).await;
    let r = sqlx::query_scalar("SELECT public.epigraph_define_group_role($1, $2, $3, $4, $5, $6)")
        .bind(key)
        .bind("synthetic team role")
        .bind(group)
        .bind(member_role)
        .bind(include_agents)
        .bind("role membership test")
        .fetch_one(&mut *c)
        .await;
    reset(c).await;
    r
}

/// `epigraph_bind_group_role` on a maintenance session (an existing role).
async fn bind(
    pool: &PgPool,
    role: &str,
    group: Uuid,
    member_role: &str,
    include_agents: bool,
) -> Result<Uuid, sqlx::Error> {
    let mut c = maint(pool).await;
    let r = sqlx::query_scalar("SELECT public.epigraph_bind_group_role($1, $2, $3, $4, $5)")
        .bind(role)
        .bind(group)
        .bind(member_role)
        .bind(include_agents)
        .bind("role membership test")
        .fetch_one(&mut *c)
        .await;
    reset(c).await;
    r
}

async fn end_binding(pool: &PgPool, binding: Uuid) -> Result<bool, sqlx::Error> {
    let mut c = maint(pool).await;
    let r = sqlx::query_scalar("SELECT public.epigraph_end_group_role_binding($1, $2)")
        .bind(binding)
        .bind("role membership test end")
        .fetch_one(&mut *c)
        .await;
    reset(c).await;
    r
}

/// Grant `role` to `holder` on a maintenance session (123's definer), its
/// window `[now() + from_s, now() + to_s)`; `to_s` `None` is open-ended. No
/// custodian exists in these tests, so no grantor is named (123's bootstrap).
async fn grant(pool: &PgPool, role: &str, holder: Uuid, from_s: i32, to_s: Option<i32>) -> Uuid {
    let mut c = maint(pool).await;
    let id: Uuid = sqlx::query_scalar(
        "SELECT public.epigraph_grant_role($1, $2, now() + make_interval(secs => $3), \
                CASE WHEN $4::int IS NULL THEN NULL \
                     ELSE now() + make_interval(secs => $4::int) END, \
                NULL, 'role membership test')",
    )
    .bind(role)
    .bind(holder)
    .bind(from_s)
    .bind(to_s)
    .fetch_one(&mut *c)
    .await
    .expect("grant the role");
    reset(c).await;
    id
}

async fn end_role(pool: &PgPool, assignment: Uuid) -> bool {
    let mut c = maint(pool).await;
    let r: bool = sqlx::query_scalar("SELECT public.epigraph_end_role_assignment($1, $2)")
        .bind(assignment)
        .bind("role membership test end")
        .fetch_one(&mut *c)
        .await
        .expect("end the assignment");
    reset(c).await;
    r
}

async fn arm(pool: &PgPool) {
    let mut c = maint(pool).await;
    sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
        .fetch_one(&mut *c)
        .await
        .expect("the maintenance role arms");
    reset(c).await;
}

/// `(readable, writable)`: whether `agent`'s `Viewer::resolve` carries `group`
/// in its read set and in its write set.
async fn resolves(pool: &PgPool, agent: Uuid, group: Uuid) -> (bool, bool) {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    (
        viewer.group_bind().is_some_and(|g| g.contains(&group)),
        viewer.writable_groups().contains(&group),
    )
}

/// The roles `epigraph_live_memberships` answers for `(agent, group)`.
async fn live_roles(pool: &PgPool, agent: Uuid, group: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT role FROM public.epigraph_live_memberships($1) WHERE group_id = $2 ORDER BY 1",
    )
    .bind(agent)
    .bind(group)
    .fetch_all(pool)
    .await
    .expect("live memberships")
}

/// A `('group', group)` claim authored by `author`, inserted on an
/// `epigraph_app` session stamped as `principal` with read set `read` and
/// write set `write`.
async fn write_stamped(
    pool: &PgPool,
    principal: Uuid,
    read: &[Uuid],
    write: &[Uuid],
    author: Uuid,
    group: Uuid,
) -> Result<Uuid, sqlx::Error> {
    write_stamped_valve(pool, principal, read, write, author, group, false).await
}

/// [`write_stamped`], optionally with the session's OPL01 valve
/// (`epigraph.operator_link_enforcement = 'off'`) opened first: an
/// application session can set it, and it relieves the link binding (OPL01)
/// only, never the writer scope (OPL02).
async fn write_stamped_valve(
    pool: &PgPool,
    principal: Uuid,
    read: &[Uuid],
    write: &[Uuid],
    author: Uuid,
    group: Uuid,
    valve_off: bool,
) -> Result<Uuid, sqlx::Error> {
    let join = |s: &[Uuid]| {
        s.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let (read, write) = (join(read), join(write));
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $3, false)",
        )
        .bind(principal.to_string())
        .bind(&read)
        .bind(&write)
        .execute(&mut *conn)
        .await
        .expect("stamp");
        sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', $1, false)")
            .bind(if valve_off { "off" } else { "" })
            .execute(&mut *conn)
            .await
            .expect("valve");
        let id = Uuid::new_v4();
        let r = sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id) \
             VALUES ($1, $2, $3, 0.5, $4, true, 'group', $5)",
        )
        .bind(id)
        .bind(format!("role membership probe {id}"))
        .bind(id.as_bytes().repeat(2))
        .bind(author)
        .bind(group)
        .execute(&mut *conn)
        .await
        .map(|_| id);
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false), \
                    set_config('epigraph.operator_link_enforcement', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, r)
    })
    .await
}

/// `principal` writes its own claim into `group`, stamped exactly as its
/// resolved viewer says (the request path).
async fn write_honest(pool: &PgPool, principal: Uuid, group: Uuid) -> Result<Uuid, sqlx::Error> {
    let viewer = Viewer::resolve(pool, principal).await.expect("resolve");
    let read = viewer.group_bind().unwrap_or_default().to_vec();
    let write = viewer.writable_groups().to_vec();
    write_stamped(pool, principal, &read, &write, principal, group).await
}

/// `principal` writes its own claim into `group` with a stamp FORGED to name
/// the group in both sets (any holder of the application DSN can set them).
async fn write_forged(pool: &PgPool, principal: Uuid, group: Uuid) -> Result<Uuid, sqlx::Error> {
    write_stamped(pool, principal, &[group], &[group], principal, group).await
}

/// [`write_forged`] with the session's OPL01 valve open.
async fn write_forged_valve_off(
    pool: &PgPool,
    principal: Uuid,
    group: Uuid,
) -> Result<Uuid, sqlx::Error> {
    write_stamped_valve(pool, principal, &[group], &[group], principal, group, true).await
}

/// Every membership row of `group`: `(agent, epoch, role, revoked)`.
async fn roster_rows(pool: &PgPool, group: Uuid) -> Vec<(Uuid, i32, String, bool)> {
    sqlx::query_as(
        "SELECT agent_id, epoch, role::text, revoked_at IS NOT NULL FROM group_memberships \
          WHERE group_id = $1 ORDER BY agent_id, epoch",
    )
    .bind(group)
    .fetch_all(pool)
    .await
    .expect("roster rows")
}

async fn events(pool: &PgPool, event_type: &str, key: &str, id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = $1 AND details->>$2 = $3::text",
    )
    .bind(event_type)
    .bind(key)
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("events")
}

/// One team group administered by its own human, with `ROLE` defined and
/// bound to it at `member_role`. Returns `(group, binding)`.
async fn bound_group(pool: &PgPool, name: &str, member_role: &str, agents: bool) -> (Uuid, Uuid) {
    let (owner, _) = human(pool, &format!("{name}-owner")).await;
    let group = team_group(pool, name, owner).await;
    let binding = define(pool, ROLE, group, member_role, agents)
        .await
        .expect("define the role and bind it");
    (group, binding)
}

// =====================================================================
// Catalog: who may call what.
// =====================================================================

/// `(prosecdef, owner, proacl, proconfig)` of one function.
type CatalogRow = (bool, String, Option<String>, Option<Vec<String>>);

/// The five new functions are `SECURITY DEFINER`, owned by
/// `epigraph_maintenance`, pin their search path, and are NOT executable by
/// PUBLIC or the application role: the derived-membership helper and the
/// roster answer for ANY principal (an unbound
/// roster read is an oracle, 123's rule), and the three binding verbs are
/// maintenance acts. `epigraph_live_memberships(uuid)` keeps exactly the
/// signature, result and application grant every viewer (and every pinned
/// downstream crate) calls. Pinned in the catalog because the harness migrates
/// as a superuser: a silently no-opped `OWNER TO` or a stray grant would pass
/// every behavioural test.
#[sqlx::test(migrations = "../../migrations")]
async fn the_new_helpers_are_maintenance_definers_the_app_role_cannot_call(pool: PgPool) {
    for signature in [
        "public.epigraph_role_derived_memberships(uuid, timestamp with time zone)",
        "public.epigraph_group_role_roster(uuid, timestamp with time zone)",
        "public.epigraph_define_group_role(text, text, uuid, text, boolean, text)",
        "public.epigraph_bind_group_role(text, uuid, text, boolean, text)",
        "public.epigraph_end_group_role_binding(uuid, text)",
    ] {
        let row: Option<CatalogRow> = sqlx::query_as(
            "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, p.proacl::text, \
                    p.proconfig \
               FROM pg_proc p WHERE p.oid = to_regprocedure($1)",
        )
        .bind(signature)
        .fetch_optional(&pool)
        .await
        .expect("catalog read");
        let Some((secdef, owner, acl, config)) = row else {
            panic!("{signature} does not exist");
        };
        assert!(secdef, "{signature} must be SECURITY DEFINER");
        assert_eq!(owner, "epigraph_maintenance", "{signature} owner");
        let acl = acl.unwrap_or_default();
        assert!(
            !acl.contains("epigraph_app="),
            "{signature}: the application role must not hold EXECUTE: {acl}"
        );
        assert!(
            !acl.contains("{=X") && !acl.contains(",=X"),
            "{signature}: PUBLIC must not hold EXECUTE: {acl}"
        );
        assert!(
            config
                .unwrap_or_default()
                .iter()
                .any(|c| c.starts_with("search_path=")),
            "{signature} must pin its search_path"
        );
        for (role, expected) in [("epigraph_app", false), ("epigraph_maintenance", true)] {
            let can: bool = sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
                .bind(role)
                .bind(signature)
                .fetch_one(&pool)
                .await
                .expect("function privilege");
            assert_eq!(can, expected, "{role} EXECUTE on {signature}");
        }
    }

    // POSITIVE CONTROL: the viewer's read keeps its signature, its result
    // shape, its owner and its application grant.
    let (owner, result, app_can): (String, String, bool) = sqlx::query_as(
        "SELECT pg_get_userbyid(p.proowner)::text, pg_get_function_result(p.oid), \
                has_function_privilege('epigraph_app', p.oid, 'EXECUTE') \
           FROM pg_proc p WHERE p.oid = to_regprocedure('public.epigraph_live_memberships(uuid)')",
    )
    .fetch_one(&pool)
    .await
    .expect("live memberships catalog row");
    assert_eq!(owner, "epigraph_maintenance");
    assert_eq!(result, "TABLE(group_id uuid, role text)");
    assert!(app_can, "Viewer::resolve calls it on the application role");
    let scope_app_can: bool = sqlx::query_scalar(
        "SELECT has_function_privilege('epigraph_app', \
                'public.epigraph_require_writer_scope(uuid, uuid)', 'EXECUTE')",
    )
    .fetch_one(&pool)
    .await
    .expect("writer scope grant");
    assert!(
        scope_app_can,
        "the claims trigger calls it on the application role"
    );
}

/// The application role cannot reach a roster through any of the new
/// functions, whatever it forges: each call is refused 42501. The identical
/// calls on a maintenance session answer.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_has_no_roster_oracle(pool: PgPool) {
    let (h, _) = human(&pool, "oracle-h").await;
    let (group, _) = bound_group(&pool, "Synthetic Oracle Team", "writer", true).await;
    grant(&pool, ROLE, h, 0, None).await;

    let calls = [
        "SELECT count(*) FROM public.epigraph_role_derived_memberships($1, now()) \
          WHERE group_id = $2",
        "SELECT count(*) FROM public.epigraph_group_role_roster($2, now()) WHERE true \
            AND $1::uuid IS NOT NULL",
    ];
    for sql in calls {
        let r: Result<i64, _> = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
                .bind(h.to_string())
                .execute(&mut *conn)
                .await
                .expect("stamp");
            let r = sqlx::query_scalar(sql)
                .bind(h)
                .bind(group)
                .fetch_one(&mut *conn)
                .await;
            (conn, r)
        })
        .await;
        assert_eq!(code_of(&r).as_deref(), Some("42501"), "app: {sql}: {r:?}");

        let mut c = maint(&pool).await;
        let n: i64 = sqlx::query_scalar(sql)
            .bind(h)
            .bind(group)
            .fetch_one(&mut *c)
            .await
            .unwrap_or_else(|e| panic!("POSITIVE CONTROL, maintenance: {sql}: {e}"));
        reset(c).await;
        assert_eq!(n, 1, "maintenance answers: {sql}");
    }
}

/// Only a maintenance session writes `group_role_bindings`, and only through
/// its rules: the application role inserts, updates and deletes nothing and
/// reads no binding (row security), cannot run the binding verbs, cannot add
/// a catalog role and cannot forge the binding audit family. A binding is
/// append-only even for maintenance: only an end, once; never a DELETE. The
/// fresh catalog is the two public roles; defining one adds exactly one.
#[sqlx::test(migrations = "../../migrations")]
async fn only_maintenance_writes_bindings_and_a_binding_is_only_ever_ended(pool: PgPool) {
    let catalog = |pool: PgPool| async move {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM platform_roles")
            .fetch_one(&pool)
            .await
            .expect("catalog")
    };
    assert_eq!(catalog(pool.clone()).await, 2, "a fresh catalog is public");
    let (owner, _) = human(&pool, "rows-owner").await;
    let group = team_group(&pool, "Synthetic Rows Team", owner).await;
    let binding = define(&pool, ROLE, group, "writer", true)
        .await
        .expect("POSITIVE CONTROL: maintenance defines");
    assert_eq!(catalog(pool.clone()).await, 3, "one role added");
    let (elevates, audit): (bool, bool) =
        sqlx::query_as("SELECT elevates, reads_audit FROM platform_roles WHERE key = $1")
            .bind(ROLE)
            .fetch_one(&pool)
            .await
            .expect("the defined role");
    assert!(
        !elevates && !audit,
        "a defined role confers no platform power"
    );
    assert_eq!(
        events(&pool, "platform.group_role_bound", "binding_id", binding).await,
        1,
        "the binding is audited"
    );

    let app = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $2, false), \
                    set_config('epigraph.operator_link_enforcement', 'off', false)",
        )
        .bind(owner.to_string())
        .bind(group.to_string())
        .execute(&mut *conn)
        .await
        .expect("forge");
        let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM group_role_bindings")
            .fetch_one(&mut *conn)
            .await
            .unwrap_or(-1);
        let ins = sqlx::query(
            "INSERT INTO group_role_bindings (group_id, role, member_role, include_agents, reason) \
             VALUES ($1, $2, 'writer', true, 'forged')",
        )
        .bind(group)
        .bind(ROLE)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected());
        let upd =
            sqlx::query("UPDATE group_role_bindings SET include_agents = false WHERE id = $1")
                .bind(binding)
                .execute(&mut *conn)
                .await
                .map(|r| r.rows_affected());
        let del = sqlx::query("DELETE FROM group_role_bindings WHERE id = $1")
            .bind(binding)
            .execute(&mut *conn)
            .await
            .map(|r| r.rows_affected());
        let role = sqlx::query(
            "INSERT INTO platform_roles (key, elevates, reads_audit, role_node_id, description) \
             VALUES ('role:forged', false, false, $1, 'forged')",
        )
        .bind(owner)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected());
        let verb = sqlx::query_scalar::<_, Uuid>(
            "SELECT public.epigraph_bind_group_role($1, $2, 'writer', true, 'forged')",
        )
        .bind(ROLE)
        .bind(group)
        .fetch_one(&mut *conn)
        .await;
        let end = sqlx::query_scalar::<_, bool>(
            "SELECT public.epigraph_end_group_role_binding($1, 'forged')",
        )
        .bind(binding)
        .fetch_one(&mut *conn)
        .await;
        let forged_event = sqlx::query(
            "INSERT INTO security_events (event_type, agent_id, success, details) \
             VALUES ('platform.group_role_bound', $1, true, '{}'::jsonb)",
        )
        .bind(owner)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected());
        (conn, (seen, ins, upd, del, role, verb, end, forged_event))
    })
    .await;
    let (seen, ins, upd, del, role, verb, end, forged_event) = app;
    assert_eq!(
        seen, 0,
        "row security hides every binding from the app role"
    );
    assert_eq!(
        code_of(&ins).as_deref(),
        Some("42501"),
        "app INSERT: {ins:?}"
    );
    assert!(
        matches!(upd, Ok(0)) || code_of(&upd).as_deref() == Some("42501"),
        "app UPDATE changes nothing: {upd:?}"
    );
    assert!(
        matches!(del, Ok(0)) || code_of(&del).as_deref() == Some("42501"),
        "app DELETE changes nothing: {del:?}"
    );
    assert_eq!(
        code_of(&role).as_deref(),
        Some("42501"),
        "app catalog INSERT: {role:?}"
    );
    assert_eq!(
        code_of(&verb).as_deref(),
        Some("42501"),
        "app bind: {verb:?}"
    );
    assert_eq!(code_of(&end).as_deref(), Some("42501"), "app end: {end:?}");
    assert_eq!(
        code_of(&forged_event).as_deref(),
        Some("42501"),
        "app forged audit row: {forged_event:?}"
    );
    let (include, live): (bool, bool) = sqlx::query_as(
        "SELECT include_agents, revoked_at IS NULL FROM group_role_bindings WHERE id = $1",
    )
    .bind(binding)
    .fetch_one(&pool)
    .await
    .expect("binding row");
    assert!(include && live, "the binding is unchanged");

    // Append-only for maintenance too: no field changes, no delete.
    let mut c = maint(&pool).await;
    let upd = sqlx::query("UPDATE group_role_bindings SET include_agents = false WHERE id = $1")
        .bind(binding)
        .execute(&mut *c)
        .await;
    let del = sqlx::query("DELETE FROM group_role_bindings WHERE id = $1")
        .bind(binding)
        .execute(&mut *c)
        .await;
    reset(c).await;
    assert!(upd.is_err(), "maintenance cannot edit a binding: {upd:?}");
    assert!(del.is_err(), "maintenance cannot delete a binding: {del:?}");

    assert!(end_binding(&pool, binding).await.expect("end"), "ended");
    assert!(
        !end_binding(&pool, binding).await.expect("end again"),
        "an end is never repeated"
    );
    assert_eq!(
        events(&pool, "platform.group_role_unbound", "binding_id", binding).await,
        1,
        "one end, one audit row"
    );
}

/// On a maintenance session in one transaction: set the acting-process
/// setting (164's `epigraph.operator_actor`) to `actor`, when given, then run
/// `sql` (one text-valued column) with `binds`, and commit. Returns the value.
async fn maint_with_actor(pool: &PgPool, actor: Option<&str>, sql: &str, binds: &[&str]) -> String {
    let mut c = maint(pool).await;
    let out = {
        let mut tx = sqlx::Connection::begin(&mut *c).await.expect("begin");
        if let Some(actor) = actor {
            sqlx::query("SELECT set_config('epigraph.operator_actor', $1, true)")
                .bind(actor)
                .execute(&mut *tx)
                .await
                .expect("set the actor");
        }
        let mut q = sqlx::query_scalar::<_, String>(sql);
        for b in binds {
            q = q.bind(*b);
        }
        let v = q.fetch_one(&mut *tx).await.expect("the verb");
        tx.commit().await.expect("commit");
        v
    };
    reset(c).await;
    out
}

/// `details` of the one `event_type` row whose `details->>key` is `id`.
async fn event_details(pool: &PgPool, event_type: &str, key: &str, id: &str) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = $1 AND details->>$2 = $3",
    )
    .bind(event_type)
    .bind(key)
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("one {event_type} row with {key} = {id}: {e}"))
}

/// Every binding audit row names the ACTING PROCESS, not only the shared
/// maintenance login (164's `actor`, read from the transaction-local
/// `epigraph.operator_actor` the operator CLI sets), and defining a role
/// writes its own `platform.role_defined` row naming the role, its graph node
/// and the group it was defined for. With no actor set, the key is present
/// and null, so the row says "not recorded" rather than omitting it.
#[sqlx::test(migrations = "../../migrations")]
async fn binding_audit_rows_name_the_acting_process_and_a_define_is_recorded(pool: PgPool) {
    let (owner, _) = human(&pool, "audit-owner").await;
    let group = team_group(&pool, "Synthetic Audit Team", owner).await;
    let g = group.to_string();

    let binding: Uuid = maint_with_actor(
        &pool,
        Some(r#"{"tool":"synthetic-define-probe"}"#),
        "SELECT public.epigraph_define_group_role($1, 'synthetic team role', $2::uuid, \
                'writer', true, 'audit test')::text",
        &[ROLE, &g],
    )
    .await
    .parse()
    .expect("a binding id");
    let bound = event_details(
        &pool,
        "platform.group_role_bound",
        "binding_id",
        &binding.to_string(),
    )
    .await;
    assert_eq!(
        bound["actor"]["tool"], "synthetic-define-probe",
        "the bound row names the acting process: {bound}"
    );
    let node: Uuid = sqlx::query_scalar("SELECT role_node_id FROM platform_roles WHERE key = $1")
        .bind(ROLE)
        .fetch_one(&pool)
        .await
        .expect("the defined role");
    let defined = event_details(&pool, "platform.role_defined", "role", ROLE).await;
    assert_eq!(defined["role_node_id"], node.to_string(), "{defined}");
    assert_eq!(defined["group_id"], g, "{defined}");
    assert_eq!(
        defined["actor"]["tool"], "synthetic-define-probe",
        "{defined}"
    );
    assert_eq!(defined["elevates"], false, "{defined}");
    assert_eq!(defined["reads_audit"], false, "{defined}");

    let ended = maint_with_actor(
        &pool,
        Some(r#"{"tool":"synthetic-end-probe"}"#),
        "SELECT public.epigraph_end_group_role_binding($1::uuid, 'audit test end')::text",
        &[&binding.to_string()],
    )
    .await;
    assert_eq!(ended, "true", "ended");
    let unbound = event_details(
        &pool,
        "platform.group_role_unbound",
        "binding_id",
        &binding.to_string(),
    )
    .await;
    assert_eq!(unbound["actor"]["tool"], "synthetic-end-probe", "{unbound}");

    // No actor set: the key is present and null.
    let again: Uuid = maint_with_actor(
        &pool,
        None,
        "SELECT public.epigraph_bind_group_role($1, $2::uuid, 'writer', true, 'audit test')::text",
        &[ROLE, &g],
    )
    .await
    .parse()
    .expect("a binding id");
    let bare = event_details(
        &pool,
        "platform.group_role_bound",
        "binding_id",
        &again.to_string(),
    )
    .await;
    assert!(
        bare.as_object().is_some_and(|o| o.contains_key("actor")) && bare["actor"].is_null(),
        "no actor set: recorded as null, not omitted: {bare}"
    );
}

/// No binding rides on a role that elevates or reads the audit trail
/// (GRB01), none binds a personal group (GRB02), none confers `admin` (the
/// definer refuses it, and so does the table's CHECK on a direct maintenance
/// insert), a key already in the catalog is not defined again (GRB03), and a
/// derived member is never the group's admin.
#[sqlx::test(migrations = "../../migrations")]
async fn no_binding_escalates(pool: PgPool) {
    let (owner, personal) = human(&pool, "esc-owner").await;
    let group = team_group(&pool, "Synthetic Escalation Team", owner).await;
    for elevated in ["role:platform-custodian", "role:auditor"] {
        let r = bind(&pool, elevated, group, "writer", true).await;
        assert_refused(&r, NOT_BINDABLE_ROLE, "", elevated);
    }
    let r = define(&pool, ROLE, group, "admin", true).await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some("22023"),
        "admin binding: {r:?}"
    );
    let r = define(&pool, ROLE, personal, "writer", true).await;
    assert_refused(&r, NOT_BINDABLE_GROUP, "", "a personal group");
    let binding = define(&pool, ROLE, group, "writer", true)
        .await
        .expect("POSITIVE CONTROL: a team group, a non-elevating role, writer");
    let r = define(&pool, ROLE, group, "writer", true).await;
    assert_refused(&r, ROLE_KEY_TAKEN, "", "the key is taken");

    let mut c = maint(&pool).await;
    let direct = sqlx::query(
        "INSERT INTO group_role_bindings (group_id, role, member_role, include_agents, reason) \
         VALUES ($1, $2, 'admin', true, 'direct')",
    )
    .bind(group)
    .bind(ROLE)
    .execute(&mut *c)
    .await;
    let elevated_direct = sqlx::query(
        "INSERT INTO group_role_bindings (group_id, role, member_role, include_agents, reason) \
         VALUES ($1, 'role:platform-custodian', 'writer', true, 'direct')",
    )
    .bind(group)
    .execute(&mut *c)
    .await;
    reset(c).await;
    assert_eq!(code_of(&direct).as_deref(), Some("23514"), "{direct:?}");
    assert_eq!(
        code_of(&elevated_direct).as_deref(),
        Some(NOT_BINDABLE_ROLE),
        "the table's own guard, not only the definer: {elevated_direct:?}"
    );

    let (h, _) = human(&pool, "esc-h").await;
    grant(&pool, ROLE, h, 0, None).await;
    assert_eq!(live_roles(&pool, h, group).await, ["writer"]);
    let is_admin: bool = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(h.to_string())
            .execute(&mut *conn)
            .await
            .expect("stamp");
        let a = sqlx::query_scalar("SELECT public.epigraph_is_group_admin($1)")
            .bind(group)
            .fetch_one(&mut *conn)
            .await
            .expect("is admin");
        (conn, a)
    })
    .await;
    assert!(!is_admin, "a derived member never administers the group");
    let _ = binding;
}

// =====================================================================
// The window.
// =====================================================================

/// Before `valid_from` the role confers nothing: neither the human nor its
/// agent resolves the group, and (armed) a write stamped with it is refused
/// OPL02 for both. Once the window opens, with nothing written in between,
/// both resolve it and their honest writes land.
#[sqlx::test(migrations = "../../migrations")]
async fn nothing_is_derived_before_the_window_opens(pool: PgPool) {
    let (h, _) = human(&pool, "start-h").await;
    let a = operated(&pool, h, "start-a").await;
    let (group, _) = bound_group(&pool, "Synthetic Start Team", "writer", true).await;
    grant(&pool, ROLE, h, 5, None).await;
    arm(&pool).await;

    assert_eq!(resolves(&pool, h, group).await, (false, false), "human");
    assert_eq!(resolves(&pool, a, group).await, (false, false), "agent");
    assert_refused(
        &write_forged(&pool, h, group).await,
        OPL02,
        HUMAN_SCOPE,
        "human",
    );
    assert_refused(
        &write_forged(&pool, a, group).await,
        OPL02,
        AGENT_SCOPE,
        "agent",
    );

    tokio::time::sleep(Duration::from_secs(8)).await;
    assert_eq!(resolves(&pool, h, group).await, (true, true), "human, open");
    assert_eq!(resolves(&pool, a, group).await, (true, true), "agent, open");
    write_honest(&pool, h, group)
        .await
        .expect("POSITIVE CONTROL: the human writes in the window");
    write_honest(&pool, a, group)
        .await
        .expect("POSITIVE CONTROL: its agent writes in the window");
}

/// At `valid_to` the membership lapses on the next resolution, with no job and
/// no membership row written: the human and its agent resolve the group (and
/// write it) inside the window, and after it neither resolves it, and a write
/// stamped (forged) with the group is refused OPL02 for both. The human's
/// personal group is untouched, and the group's roster table is byte-for-byte
/// what it was.
#[sqlx::test(migrations = "../../migrations")]
async fn membership_lapses_at_valid_to_with_no_job(pool: PgPool) {
    let (h, personal) = human(&pool, "end-h").await;
    let a = operated(&pool, h, "end-a").await;
    let (group, _) = bound_group(&pool, "Synthetic End Team", "writer", true).await;
    grant(&pool, ROLE, h, 0, Some(5)).await;
    arm(&pool).await;

    assert_eq!(resolves(&pool, h, group).await, (true, true), "human, in");
    assert_eq!(resolves(&pool, a, group).await, (true, true), "agent, in");
    write_honest(&pool, h, group)
        .await
        .expect("POSITIVE CONTROL: the human writes in the window");
    write_honest(&pool, a, group)
        .await
        .expect("POSITIVE CONTROL: its agent writes in the window");
    let before = roster_rows(&pool, group).await;
    assert!(
        before.iter().all(|(agent, ..)| *agent != h && *agent != a),
        "derived membership is never written: {before:?}"
    );

    tokio::time::sleep(Duration::from_secs(8)).await;
    assert_eq!(
        resolves(&pool, h, group).await,
        (false, false),
        "human, lapsed"
    );
    assert_eq!(
        resolves(&pool, a, group).await,
        (false, false),
        "agent, lapsed"
    );
    assert_refused(
        &write_forged(&pool, h, group).await,
        OPL02,
        HUMAN_SCOPE,
        "human",
    );
    assert_refused(
        &write_forged(&pool, a, group).await,
        OPL02,
        AGENT_SCOPE,
        "agent",
    );
    assert_eq!(
        roster_rows(&pool, group).await,
        before,
        "no row was written"
    );
    assert!(
        resolves(&pool, h, personal).await.1,
        "POSITIVE CONTROL: the lapse is scoped to the bound group"
    );
}

/// Ending the assignment mid-window lapses the human and its agent at once,
/// and writes exactly one `platform.role_ended` row.
#[sqlx::test(migrations = "../../migrations")]
async fn ending_the_assignment_lapses_at_once(pool: PgPool) {
    let (h, _) = human(&pool, "cut-h").await;
    let a = operated(&pool, h, "cut-a").await;
    let (group, _) = bound_group(&pool, "Synthetic Cut Team", "writer", true).await;
    let assignment = grant(&pool, ROLE, h, 0, Some(3600)).await;
    assert_eq!(resolves(&pool, a, group).await, (true, true), "PREMISE");
    assert!(end_role(&pool, assignment).await);
    assert_eq!(resolves(&pool, h, group).await, (false, false), "human");
    assert_eq!(resolves(&pool, a, group).await, (false, false), "agent");
    assert_eq!(
        events(&pool, "platform.role_ended", "assignment_id", assignment).await,
        1
    );
}

// =====================================================================
// Who is "registered to" the human.
// =====================================================================

/// A RETIRED-linked agent never derives, while a live-linked agent of the
/// same human does.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_link_never_derives(pool: PgPool) {
    let (h, _) = human(&pool, "ret-h").await;
    let live = operated(&pool, h, "ret-live").await;
    let old = retired(&pool, h, "ret-old").await;
    let (group, _) = bound_group(&pool, "Synthetic Retired Team", "writer", true).await;
    grant(&pool, ROLE, h, 0, None).await;
    assert_eq!(
        resolves(&pool, live, group).await,
        (true, true),
        "live link"
    );
    assert_eq!(
        resolves(&pool, old, group).await,
        (false, false),
        "retired link"
    );
    assert!(live_roles(&pool, old, group).await.is_empty());
}

/// Revoking an agent's ACTING row (the deactivation lever: a live link is
/// never retired in place) removes the agent and leaves its human; an agent
/// linked mid-window derives at once.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deactivated_agent_never_derives_and_a_new_link_does_at_once(pool: PgPool) {
    let (h, personal) = human(&pool, "deact-h").await;
    let a = operated(&pool, h, "deact-a").await;
    let (group, _) = bound_group(&pool, "Synthetic Deactivated Team", "writer", true).await;
    grant(&pool, ROLE, h, 0, None).await;
    assert_eq!(resolves(&pool, a, group).await, (true, true), "PREMISE");

    let mut c = maint(&pool).await;
    let n = sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(personal)
    .bind(a)
    .execute(&mut *c)
    .await
    .expect("revoke the acting row")
    .rows_affected();
    reset(c).await;
    assert_eq!(n, 1, "PREMISE: one acting row");
    assert_eq!(
        resolves(&pool, a, group).await,
        (false, false),
        "deactivated agent"
    );
    assert_eq!(
        resolves(&pool, h, group).await,
        (true, true),
        "its human stays"
    );

    let b = operated(&pool, h, "deact-b").await;
    assert_eq!(
        resolves(&pool, b, group).await,
        (true, true),
        "a new link derives at once"
    );
}

// =====================================================================
// The writer scope follows the derivation.
// =====================================================================

/// Revoke `agent`'s ACTING row in its human's personal group (the deactivation
/// lever; a live link is never retired in place).
async fn deactivate(pool: &PgPool, personal: Uuid, agent: Uuid) {
    let mut c = maint(pool).await;
    let n = sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(personal)
    .bind(agent)
    .execute(&mut *c)
    .await
    .expect("revoke the acting row")
    .rows_affected();
    reset(c).await;
    assert_eq!(n, 1, "PREMISE: one acting row");
}

/// Armed, the claims-path writer scope (OPL02) asks the question the viewer
/// asks, keyed on the WRITING principal: an agent whose acting row was revoked
/// derives nothing, so its write stamped (forged) with the bound group is
/// refused OPL02, although its link is live and its human holds the role. Its
/// live-linked sibling, and the human, writing the same way, are admitted.
#[sqlx::test(migrations = "../../migrations")]
async fn armed_a_deactivated_agent_is_refused_a_forged_write(pool: PgPool) {
    let (h, personal) = human(&pool, "wdeact-h").await;
    let a = operated(&pool, h, "wdeact-a").await;
    let sibling = operated(&pool, h, "wdeact-sib").await;
    let (group, _) = bound_group(&pool, "Synthetic Write Deactivated Team", "writer", true).await;
    grant(&pool, ROLE, h, 0, None).await;
    arm(&pool).await;
    deactivate(&pool, personal, a).await;
    assert_eq!(
        resolves(&pool, a, group).await,
        (false, false),
        "PREMISE: the deactivated agent does not derive"
    );

    assert_refused(
        &write_forged(&pool, a, group).await,
        OPL02,
        AGENT_SCOPE,
        "a deactivated agent of a role holder",
    );
    write_forged(&pool, sibling, group)
        .await
        .expect("POSITIVE CONTROL: its live-linked sibling writes the same way");
    write_forged(&pool, h, group)
        .await
        .expect("POSITIVE CONTROL: the role holder writes the same way");
}

/// Armed, a RETIRED-linked agent of a role holder is refused OPL02 on a forged
/// write even with its session's OPL01 valve open (an application session
/// can open it; it relieves the link binding, never the writer scope). The
/// human's live-linked agent, on the same valve setting, is admitted.
#[sqlx::test(migrations = "../../migrations")]
async fn armed_a_retired_linked_agent_is_refused_a_forged_write_with_the_valve_open(pool: PgPool) {
    let (h, _) = human(&pool, "wret-h").await;
    let live = operated(&pool, h, "wret-live").await;
    let old = retired(&pool, h, "wret-old").await;
    let (group, _) = bound_group(&pool, "Synthetic Write Retired Team", "writer", true).await;
    grant(&pool, ROLE, h, 0, None).await;
    arm(&pool).await;
    assert_eq!(
        resolves(&pool, old, group).await,
        (false, false),
        "PREMISE: the retired-linked agent does not derive"
    );

    assert_refused(
        &write_forged_valve_off(&pool, old, group).await,
        OPL02,
        AGENT_SCOPE,
        "a retired-linked agent of a role holder, valve open",
    );
    write_forged_valve_off(&pool, live, group)
        .await
        .expect("POSITIVE CONTROL: the live-linked agent writes on the same valve setting");
}

/// One `('group', group)` claim authored by `author` on `conn` as it stands.
async fn insert_group_claim(
    conn: &mut sqlx::PgConnection,
    author: Uuid,
    group: Uuid,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'group', $5)",
    )
    .bind(id)
    .bind(format!("role membership probe {id}"))
    .bind(id.as_bytes().repeat(2))
    .bind(author)
    .bind(group)
    .execute(conn)
    .await
    .map(|_| id)
}

/// On one `epigraph_app` session stamped as `principal`'s resolved viewer
/// (resolved now), one transaction: an INSERT into `group`, then a sleep of
/// `sleep_s` seconds, then another INSERT. Rolled back. Returns both results.
async fn one_transaction_across(
    pool: &PgPool,
    principal: Uuid,
    group: Uuid,
    sleep_s: f64,
) -> (Result<Uuid, sqlx::Error>, Result<Uuid, sqlx::Error>) {
    let viewer = Viewer::resolve(pool, principal).await.expect("resolve");
    let read = viewer
        .group_bind()
        .unwrap_or_default()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let write = viewer
        .writable_groups()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $3, false)",
        )
        .bind(principal.to_string())
        .bind(&read)
        .bind(&write)
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let out = {
            let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
            let first = insert_group_claim(&mut tx, principal, group).await;
            let _ = sqlx::query("SELECT pg_sleep($1)")
                .bind(sleep_s)
                .execute(&mut *tx)
                .await;
            let second = insert_group_claim(&mut tx, principal, group).await;
            let _ = tx.rollback().await;
            (first, second)
        };
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

/// Armed, a claim write lapses at `valid_to` STATEMENT by statement, not at
/// the next transaction: a transaction opened inside the window, whose first
/// INSERT lands, is refused OPL02 on an INSERT made after `valid_to`, for the
/// human and for its agent (`now()` is the transaction's start, so the writer
/// scope reads the clock instead).
#[sqlx::test(migrations = "../../migrations")]
async fn armed_a_transaction_opened_in_the_window_writes_nothing_after_it(pool: PgPool) {
    let (h, _) = human(&pool, "txn-h").await;
    let a = operated(&pool, h, "txn-a").await;
    let (group, _) = bound_group(&pool, "Synthetic Transaction Team", "writer", true).await;
    grant(&pool, ROLE, h, 0, Some(5)).await;
    arm(&pool).await;

    let (human_run, agent_run) = tokio::join!(
        one_transaction_across(&pool, h, group, 8.0),
        one_transaction_across(&pool, a, group, 8.0),
    );
    human_run
        .0
        .as_ref()
        .expect("POSITIVE CONTROL: the human's INSERT inside the window lands");
    agent_run
        .0
        .as_ref()
        .expect("POSITIVE CONTROL: the agent's INSERT inside the window lands");
    assert_refused(
        &human_run.1,
        OPL02,
        HUMAN_SCOPE,
        "the human, same transaction, after valid_to",
    );
    assert_refused(
        &agent_run.1,
        OPL02,
        AGENT_SCOPE,
        "the agent, same transaction, after valid_to",
    );
}

/// A revoked registration, or a suspended human client, ends the human's and
/// its agents' derived membership; the assignment row itself is untouched (the
/// role function re-checks the human).
#[sqlx::test(migrations = "../../migrations")]
async fn a_human_who_is_no_longer_registered_derives_nothing(pool: PgPool) {
    let (h, _) = human(&pool, "status-h").await;
    let a = operated(&pool, h, "status-a").await;
    let (s, _) = human(&pool, "status-s").await;
    let sa = operated(&pool, s, "status-sa").await;
    let (group, _) = bound_group(&pool, "Synthetic Status Team", "writer", true).await;
    let ha = grant(&pool, ROLE, h, 0, None).await;
    grant(&pool, ROLE, s, 0, None).await;
    for who in [h, a, s, sa] {
        assert_eq!(
            resolves(&pool, who, group).await,
            (true, true),
            "PREMISE {who}"
        );
    }

    let mut c = maint(&pool).await;
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_now FROM public.epigraph_revoke_human_operator($1, $2)")
            .bind(h)
            .bind("role membership test")
            .fetch_one(&mut *c)
            .await
            .expect("revoke the registration");
    reset(c).await;
    assert!(revoked);
    sqlx::query("UPDATE oauth_clients SET status = 'suspended' WHERE agent_id = $1 AND client_type = 'human'")
        .bind(s)
        .execute(&pool)
        .await
        .expect("suspend the human client");

    for (who, what) in [
        (h, "revoked human"),
        (a, "its agent"),
        (s, "suspended human"),
        (sa, "its agent"),
    ] {
        assert_eq!(resolves(&pool, who, group).await, (false, false), "{what}");
    }
    let still: bool =
        sqlx::query_scalar("SELECT revoked_at IS NULL FROM role_assignments WHERE id = $1")
            .bind(ha)
            .fetch_one(&pool)
            .await
            .expect("assignment");
    assert!(still, "the assignment row is not touched");
}

/// A 149-allowlisted client agent of a role-holding human derives (reads,
/// and armed writes, the group) while its allowance is live, and derives
/// nothing once the allowance is revoked.
#[sqlx::test(migrations = "../../migrations")]
async fn an_allowlisted_client_derives_until_its_allowance_is_revoked(pool: PgPool) {
    let (h, _) = human(&pool, "allow-h").await;
    let (svc, client) = allowance_bound(&pool, h, "allow-svc").await;
    let (group, _) = bound_group(&pool, "Synthetic Allowance Team", "writer", true).await;
    assert_eq!(
        resolves(&pool, svc, group).await,
        (false, false),
        "no role yet"
    );
    grant(&pool, ROLE, h, 0, None).await;
    arm(&pool).await;
    assert_eq!(
        resolves(&pool, svc, group).await,
        (true, true),
        "allowlisted"
    );
    write_honest(&pool, svc, group)
        .await
        .expect("the allowlisted agent writes in the window");

    let mut c = maint(&pool).await;
    let revoked: bool = sqlx::query_scalar(
        "SELECT revoked_now FROM public.epigraph_revoke_author_binding_client($1, $2)",
    )
    .bind(client)
    .bind("role membership test")
    .fetch_one(&mut *c)
    .await
    .expect("revoke the allowance");
    reset(c).await;
    assert!(revoked);
    assert_eq!(
        resolves(&pool, svc, group).await,
        (false, false),
        "allowance revoked"
    );
    assert_eq!(
        resolves(&pool, h, group).await,
        (true, true),
        "its human stays"
    );
}

/// `Err` with one of the SQLSTATEs in `codes` (the write is refused by the
/// operator-binding layer, whichever of its checks reaches it first).
fn assert_refused_by<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>, codes: &[&str], what: &str) {
    let code = code_of(r);
    assert!(
        code.as_deref().is_some_and(|c| codes.contains(&c)),
        "{what}: expected a refusal with one of {codes:?}, got {r:?}"
    );
}

/// Armed, ENDING THE BINDING ends claim writes into the group at once, for
/// the role holder and for its agent, whatever the stamp says; both wrote the
/// same way while the binding was live.
#[sqlx::test(migrations = "../../migrations")]
async fn armed_ending_the_binding_ends_writes_at_once(pool: PgPool) {
    let (h, _) = human(&pool, "bend-h").await;
    let a = operated(&pool, h, "bend-a").await;
    let (group, binding) = bound_group(&pool, "Synthetic Binding End Team", "writer", true).await;
    grant(&pool, ROLE, h, 0, None).await;
    arm(&pool).await;
    write_forged(&pool, h, group)
        .await
        .expect("POSITIVE CONTROL: the holder writes while the binding is live");
    write_forged(&pool, a, group)
        .await
        .expect("POSITIVE CONTROL: its agent writes while the binding is live");

    assert!(end_binding(&pool, binding).await.expect("end"));
    assert_refused(
        &write_forged(&pool, h, group).await,
        OPL02,
        HUMAN_SCOPE,
        "the holder, binding ended",
    );
    assert_refused(
        &write_forged(&pool, a, group).await,
        OPL02,
        AGENT_SCOPE,
        "its agent, binding ended",
    );
}

/// Armed, a role holder whose registration is revoked, or whose human client
/// is suspended, and that human's agent, write nothing into the group with a
/// forged stamp; each wrote the same way before. (The refusing check may be
/// the link binding, OPL01, for a principal that is no longer a registered
/// human, or the writer scope, OPL02; either refuses.)
#[sqlx::test(migrations = "../../migrations")]
async fn armed_a_revoked_or_suspended_human_and_its_agent_write_nothing(pool: PgPool) {
    let (h, _) = human(&pool, "wstatus-h").await;
    let a = operated(&pool, h, "wstatus-a").await;
    let (s, _) = human(&pool, "wstatus-s").await;
    let sa = operated(&pool, s, "wstatus-sa").await;
    let (group, _) = bound_group(&pool, "Synthetic Write Status Team", "writer", true).await;
    grant(&pool, ROLE, h, 0, None).await;
    grant(&pool, ROLE, s, 0, None).await;
    arm(&pool).await;
    for (who, what) in [(h, "h"), (a, "a"), (s, "s"), (sa, "sa")] {
        write_forged(&pool, who, group)
            .await
            .unwrap_or_else(|e| panic!("POSITIVE CONTROL: {what} writes before: {e}"));
    }

    let mut c = maint(&pool).await;
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_now FROM public.epigraph_revoke_human_operator($1, $2)")
            .bind(h)
            .bind("role membership test")
            .fetch_one(&mut *c)
            .await
            .expect("revoke the registration");
    reset(c).await;
    assert!(revoked);
    sqlx::query(
        "UPDATE oauth_clients SET status = 'suspended' WHERE agent_id = $1 \
            AND client_type = 'human'",
    )
    .bind(s)
    .execute(&pool)
    .await
    .expect("suspend the human client");

    for (who, what) in [
        (h, "revoked human"),
        (a, "its agent"),
        (s, "suspended human"),
        (sa, "its agent"),
    ] {
        assert_refused_by(
            &write_forged(&pool, who, group).await,
            &["OPL01", OPL02],
            what,
        );
    }
}

/// A group that is no longer ACTIVE is neither read nor written through its
/// binding: after the group is suspended, the holder and its agent no longer
/// resolve it, and (armed) their forged writes are refused; both read and
/// wrote it while it was active.
#[sqlx::test(migrations = "../../migrations")]
async fn armed_a_suspended_group_is_neither_read_nor_written_through_its_binding(pool: PgPool) {
    let (h, _) = human(&pool, "gsusp-h").await;
    let a = operated(&pool, h, "gsusp-a").await;
    let (group, _) = bound_group(&pool, "Synthetic Suspended Team", "writer", true).await;
    grant(&pool, ROLE, h, 0, None).await;
    arm(&pool).await;
    for (who, what) in [(h, "holder"), (a, "agent")] {
        assert_eq!(
            resolves(&pool, who, group).await,
            (true, true),
            "PREMISE {what}"
        );
        write_forged(&pool, who, group)
            .await
            .unwrap_or_else(|e| panic!("POSITIVE CONTROL: the {what} writes while active: {e}"));
    }

    sqlx::query("UPDATE groups SET status = 'suspended' WHERE id = $1")
        .bind(group)
        .execute(&pool)
        .await
        .expect("suspend the group (a privileged session)");
    for (who, what) in [(h, "holder"), (a, "agent")] {
        assert_eq!(
            resolves(&pool, who, group).await,
            (false, false),
            "{what}, group suspended"
        );
        assert!(
            code_of(&write_forged(&pool, who, group).await).is_some(),
            "{what}: a forged write into a suspended group is refused"
        );
    }
}

/// A 149-allowlisted client agent lapses with its HUMAN's window, not only
/// with its allowance: inside the window it resolves and (armed) writes the
/// group; after `valid_to` it resolves nothing and a forged write is refused
/// OPL02.
#[sqlx::test(migrations = "../../migrations")]
async fn an_allowlisted_agent_lapses_at_its_humans_valid_to(pool: PgPool) {
    let (h, _) = human(&pool, "allow-end-h").await;
    let (svc, _) = allowance_bound(&pool, h, "allow-end-svc").await;
    let (group, _) = bound_group(&pool, "Synthetic Allowance End Team", "writer", true).await;
    grant(&pool, ROLE, h, 0, Some(5)).await;
    arm(&pool).await;
    assert_eq!(
        resolves(&pool, svc, group).await,
        (true, true),
        "in the window"
    );
    write_forged(&pool, svc, group)
        .await
        .expect("POSITIVE CONTROL: the allowlisted agent writes in the window");

    tokio::time::sleep(Duration::from_secs(8)).await;
    assert_eq!(
        resolves(&pool, svc, group).await,
        (false, false),
        "after valid_to"
    );
    assert_refused(
        &write_forged(&pool, svc, group).await,
        OPL02,
        AGENT_SCOPE,
        "the allowlisted agent after its human's valid_to",
    );
}

/// A human with no assignment of the role, and its agent, never derive; with
/// a forged stamp (armed) each is refused OPL02, while a role-holding human
/// and its agent write the same group.
#[sqlx::test(migrations = "../../migrations")]
async fn a_human_without_the_role_and_its_agent_are_refused(pool: PgPool) {
    let (h, _) = human(&pool, "non-h").await;
    let a = operated(&pool, h, "non-a").await;
    let (m, _) = human(&pool, "member-m").await;
    let ma = operated(&pool, m, "member-ma").await;
    let (group, _) = bound_group(&pool, "Synthetic Outsider Team", "writer", true).await;
    grant(&pool, ROLE, m, 0, None).await;
    arm(&pool).await;
    assert_eq!(resolves(&pool, h, group).await, (false, false));
    assert_eq!(resolves(&pool, a, group).await, (false, false));
    assert_refused(
        &write_forged(&pool, h, group).await,
        OPL02,
        HUMAN_SCOPE,
        "human",
    );
    assert_refused(
        &write_forged(&pool, a, group).await,
        OPL02,
        AGENT_SCOPE,
        "agent",
    );
    write_forged(&pool, m, group)
        .await
        .expect("POSITIVE CONTROL: the role holder writes");
    write_forged(&pool, ma, group)
        .await
        .expect("POSITIVE CONTROL: its agent writes");
}

/// A binding WITHOUT `include_agents` admits the human and not its agent, and
/// the writer scope honours that: the agent's forged write is refused OPL02,
/// although its human writes the group.
#[sqlx::test(migrations = "../../migrations")]
async fn a_human_only_binding_does_not_reach_the_agents(pool: PgPool) {
    let (h, _) = human(&pool, "only-h").await;
    let a = operated(&pool, h, "only-a").await;
    let (group, _) = bound_group(&pool, "Synthetic Human Only Team", "writer", false).await;
    grant(&pool, ROLE, h, 0, None).await;
    arm(&pool).await;
    assert_eq!(resolves(&pool, h, group).await, (true, true), "human");
    assert_eq!(resolves(&pool, a, group).await, (false, false), "agent");
    write_honest(&pool, h, group)
        .await
        .expect("POSITIVE CONTROL: the human writes");
    assert_refused(
        &write_forged(&pool, a, group).await,
        OPL02,
        AGENT_SCOPE,
        "agent",
    );
}

/// A `reader` binding reads and never writes: the group is in the read set
/// and not the write set, and a write stamped writable is refused OPL02 for
/// the human and its agent.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_binding_reads_and_never_writes(pool: PgPool) {
    let (h, _) = human(&pool, "reader-h").await;
    let a = operated(&pool, h, "reader-a").await;
    let (group, _) = bound_group(&pool, "Synthetic Reader Team", "reader", true).await;
    grant(&pool, ROLE, h, 0, None).await;
    arm(&pool).await;
    assert_eq!(
        resolves(&pool, h, group).await,
        (true, false),
        "human reads"
    );
    assert_eq!(
        resolves(&pool, a, group).await,
        (true, false),
        "agent reads"
    );
    assert_refused(
        &write_forged(&pool, h, group).await,
        OPL02,
        HUMAN_SCOPE,
        "human",
    );
    assert_refused(
        &write_forged(&pool, a, group).await,
        OPL02,
        AGENT_SCOPE,
        "agent",
    );
}

// =====================================================================
// The door stays direct-only.
// =====================================================================

/// A teammate holding the role, with no explicit row, gives its agent no
/// explicit membership: the team-group verb refuses GRP03 and the
/// application path's membership door refuses OPL02 (armed). Each is admitted
/// once the teammate holds an explicit writer row. This fails if anyone makes
/// `epigraph_operator_writes_group` effective, which would let an explicit
/// row outlive the window.
#[sqlx::test(migrations = "../../migrations")]
async fn the_membership_door_stays_direct_only(pool: PgPool) {
    let (t, _) = human(&pool, "door-t").await;
    let ta = operated(&pool, t, "door-ta").await;
    let (group, _) = bound_group(&pool, "Synthetic Door Team", "writer", true).await;
    grant(&pool, ROLE, t, 0, None).await;
    arm(&pool).await;
    assert_eq!(
        resolves(&pool, ta, group).await,
        (true, true),
        "PREMISE: derived"
    );

    let add = |pool: PgPool| async move {
        let mut c = maint(&pool).await;
        let r: Result<(Option<Uuid>, bool), _> = sqlx::query_as(
            "SELECT out_membership_id, out_applied \
               FROM public.epigraph_team_group_add_member($1, $2, 'writer', 'door test')",
        )
        .bind(group)
        .bind(ta)
        .fetch_one(&mut *c)
        .await;
        reset(c).await;
        r
    };
    let door = |pool: PgPool| async move {
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            let r = sqlx::query("SELECT public.epigraph_require_operator_scope($1, $2)")
                .bind(ta)
                .bind(group)
                .execute(&mut *conn)
                .await
                .map(|_| ());
            (conn, r)
        })
        .await
    };
    assert_refused(&add(pool.clone()).await, OPERATOR_SCOPE, "", "verb");
    assert_refused(&door(pool.clone()).await, OPL02, AGENT_SCOPE, "door");

    let mut c = maint(&pool).await;
    sqlx::query(
        "SELECT out_applied FROM public.epigraph_team_group_add_member($1, $2, 'writer', 'door')",
    )
    .bind(group)
    .bind(t)
    .fetch_one(&mut *c)
    .await
    .expect("an explicit writer row for the teammate");
    reset(c).await;
    door(pool.clone())
        .await
        .expect("POSITIVE CONTROL: the door admits an agent whose human has a row");
    add(pool.clone())
        .await
        .expect("POSITIVE CONTROL: the verb admits it too");
}

// =====================================================================
// Bindings and the roster.
// =====================================================================

/// The roster at an instant follows the window: nothing before the binding;
/// at an instant AFTER the binding exists but BEFORE a holder's `valid_from`,
/// that holder is absent while a holder whose window is open is present (so
/// the window's start, not the binding's, is what excludes it); inside both
/// windows, both holders (and the agent); after both, nobody. Ending the
/// binding lapses the members at once; a new binding of the same role
/// derives again.
#[sqlx::test(migrations = "../../migrations")]
async fn the_roster_follows_the_window_and_the_binding(pool: PgPool) {
    let (h, _) = human(&pool, "roster-h").await;
    let a = operated(&pool, h, "roster-a").await;
    let (late, _) = human(&pool, "roster-late").await;
    let (group, binding) = bound_group(&pool, "Synthetic Roster Team", "writer", true).await;
    grant(&pool, ROLE, h, 0, Some(3600)).await;
    // Bound already; this holder's window opens in 10 minutes.
    grant(&pool, ROLE, late, 600, Some(4200)).await;

    let roster = |pool: PgPool, at: &'static str| async move {
        let mut c = maint(&pool).await;
        let rows: Vec<(Uuid, String)> = sqlx::query_as(&format!(
            "SELECT out_agent_id, out_role FROM public.epigraph_group_role_roster($1, {at}) \
              ORDER BY 1"
        ))
        .bind(group)
        .fetch_all(&mut *c)
        .await
        .expect("roster");
        reset(c).await;
        rows
    };
    let sorted = |mut v: Vec<(Uuid, String)>| {
        v.sort();
        v
    };
    let w = |id: Uuid| (id, "writer".to_string());
    assert!(
        roster(pool.clone(), "now() - interval '1 hour'")
            .await
            .is_empty(),
        "before the binding"
    );
    assert_eq!(
        roster(pool.clone(), "now()").await,
        sorted(vec![w(h), w(a)]),
        "bound, and before the late holder's valid_from: the late holder is absent"
    );
    assert_eq!(
        roster(pool.clone(), "now() + interval '20 minutes'").await,
        sorted(vec![w(h), w(a), w(late)]),
        "inside both windows"
    );
    assert!(
        roster(pool.clone(), "now() + interval '2 hours'")
            .await
            .is_empty(),
        "after both windows"
    );

    assert!(end_binding(&pool, binding).await.expect("end"));
    assert_eq!(
        resolves(&pool, h, group).await,
        (false, false),
        "binding ended"
    );
    assert_eq!(
        resolves(&pool, a, group).await,
        (false, false),
        "binding ended"
    );
    assert!(roster(pool.clone(), "now()").await.is_empty(), "nobody now");
    bind(&pool, ROLE, group, "writer", true)
        .await
        .expect("a new binding of the same role");
    assert_eq!(
        resolves(&pool, a, group).await,
        (true, true),
        "derived again"
    );
}
