//! Migration 164: maintenance-only, audited verbs for KEYLESS team groups.
//!
//! Four `SECURITY DEFINER` functions, owned by `epigraph_maintenance` and
//! executable by that role alone:
//!
//! * `epigraph_create_team_group(name, admin, reason)`: a `kind = 'team'`
//!   group with no key material (empty `public_key`, no `group_key_epochs`
//!   row), `did_key = 'did:epigraph:group:<id>'`, created by and with a live
//!   `admin` membership for a REGISTERED HUMAN OPERATOR;
//! * `epigraph_team_group_add_member(group, agent, role, reason)`;
//! * `epigraph_team_group_remove_member(group, agent, reason)`: a REVOKE
//!   (`revoked_at` set), never a delete;
//! * `epigraph_team_group_set_member_role(group, agent, role, reason)`.
//!
//! What is pinned, each refusal next to the positive control that shows the
//! same call shape succeeds when the refused condition is absent:
//!
//! * the application role cannot EXECUTE any verb, whatever session settings
//!   it forges (principal, group sets, the enforcement valve); the identical
//!   call on a maintenance session succeeds;
//! * create, add, set-role and remove each write exactly one `security_events`
//!   row, whose `group.` event family the application role cannot forge;
//! * the last live admin can be neither removed nor demoted;
//! * an operated agent is a member (any role) only of a group its own operator
//!   WRITES, armed or not, and never an admin; an unbound or retired-linked
//!   agent is never a member; an operator cannot be removed or demoted below
//!   writer while its operated agents are live members;
//! * a removal keeps the row (`revoked_at` set), `Viewer::resolve` stops
//!   returning the group, the member's stamped application session stops
//!   reading the group's claims, and a re-add writes a NEW row;
//! * a verb-made group's roster and group row have ONE writer, the verbs: an
//!   application session stamped as the group's own admin or creator
//!   (demoted or not) writes neither, and cannot mint a group the verbs would
//!   manage; migration 092's creator arm reads the group only while the
//!   creator is a live member;
//! * the member verbs refuse every group they do not manage (GRP05).
//!
//! Every verb runs on a session whose `session_user` IS `epigraph_maintenance`
//! (`SET SESSION AUTHORIZATION`), not on the harness superuser, so the grants
//! are what is measured.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{AgentRepository, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

const INSUFFICIENT_PRIVILEGE: &str = "42501";
const NOT_A_HUMAN_ADMIN: &str = "GRP01";
const LAST_ADMIN: &str = "GRP02";
const OPERATOR_SCOPE: &str = "GRP03";
const NOT_BOUND: &str = "GRP04";
const DUPLICATE_NAME: &str = "GRP06";

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

fn code_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> Option<String> {
    r.as_ref().err().and_then(sqlstate)
}

/// What `add` / `remove` / `set-role` answer: the live membership row they
/// touched (none for a remove of a non-member), whether they wrote, and the
/// role the row held before (remove and set-role).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Act {
    membership: Option<Uuid>,
    applied: bool,
    prior_role: Option<String>,
}

/// A connection whose `session_user` is `epigraph_maintenance` (the operator
/// CLI's role). Hand it back to [`reset`].
async fn maint(pool: &PgPool) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    use sqlx::Executor;
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_maintenance")
        .await
        .expect("downgrade to the maintenance role");
    conn
}

async fn create(pool: &PgPool, name: &str, admin: Uuid) -> Result<Uuid, sqlx::Error> {
    let mut c = maint(pool).await;
    let r = sqlx::query_scalar("SELECT public.epigraph_create_team_group($1, $2, $3)")
        .bind(name)
        .bind(admin)
        .bind("team group verb test")
        .fetch_one(&mut *c)
        .await;
    reset(c).await;
    r
}

async fn add(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) -> Result<Act, sqlx::Error> {
    let mut c = maint(pool).await;
    let r: Result<(Option<Uuid>, bool), _> = sqlx::query_as(
        "SELECT out_membership_id, out_applied \
           FROM public.epigraph_team_group_add_member($1, $2, $3, $4)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .bind("team group verb test")
    .fetch_one(&mut *c)
    .await;
    reset(c).await;
    r.map(|(membership, applied)| Act {
        membership,
        applied,
        prior_role: None,
    })
}

async fn remove(pool: &PgPool, group: Uuid, agent: Uuid) -> Result<Act, sqlx::Error> {
    let mut c = maint(pool).await;
    let r: Result<(Option<Uuid>, bool, Option<String>), _> = sqlx::query_as(
        "SELECT out_membership_id, out_applied, out_prior_role \
           FROM public.epigraph_team_group_remove_member($1, $2, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind("team group verb test")
    .fetch_one(&mut *c)
    .await;
    reset(c).await;
    r.map(|(membership, applied, prior_role)| Act {
        membership,
        applied,
        prior_role,
    })
}

async fn set_role(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) -> Result<Act, sqlx::Error> {
    let mut c = maint(pool).await;
    let r: Result<(Option<Uuid>, bool, Option<String>), _> = sqlx::query_as(
        "SELECT out_membership_id, out_applied, out_prior_role \
           FROM public.epigraph_team_group_set_member_role($1, $2, $3, $4)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .bind("team group verb test")
    .fetch_one(&mut *c)
    .await;
    reset(c).await;
    r.map(|(membership, applied, prior_role)| Act {
        membership,
        applied,
        prior_role,
    })
}

/// A registered human operator with its personal group.
async fn human(pool: &PgPool, label: &str) -> Uuid {
    fixture::seed_human_operator(pool, label).await.0
}

/// An agent LIVE-linked to `operator` through migration 107's real link.
async fn operated(pool: &PgPool, operator: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let out = AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link the agent");
    assert!(out.link_live, "PREMISE: a live link: {out:?}");
    agent
}

/// An agent with a RETIRED link to `operator` (107's retired link: no
/// membership, zero write authority).
async fn retired(pool: &PgPool, operator: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_retired_agent(&mut conn, agent, operator)
        .await
        .expect("retire-link the agent");
    agent
}

async fn arm(pool: &PgPool) {
    let mut c = maint(pool).await;
    sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
        .fetch_one(&mut *c)
        .await
        .expect("the maintenance role arms");
    reset(c).await;
}

/// Every membership row of `(group, agent)`: `(epoch, role, revoked)`, oldest
/// epoch first.
async fn rows(pool: &PgPool, group: Uuid, agent: Uuid) -> Vec<(i32, String, bool)> {
    sqlx::query_as(
        "SELECT epoch, role::text, revoked_at IS NOT NULL FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 ORDER BY epoch",
    )
    .bind(group)
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("membership rows")
}

async fn live_role(pool: &PgPool, group: Uuid, agent: Uuid) -> Option<String> {
    sqlx::query_scalar(
        "SELECT role::text FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(agent)
    .fetch_optional(pool)
    .await
    .expect("live role")
}

/// The `group.*` audit rows naming `group`, oldest first:
/// `(event_type, agent_id, details)`.
async fn audit(pool: &PgPool, group: Uuid) -> Vec<(String, Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT event_type::text, agent_id, details FROM security_events \
          WHERE event_type LIKE 'group.%' AND details->>'group_id' = $1::text \
          ORDER BY created_at, id",
    )
    .bind(group)
    .fetch_all(pool)
    .await
    .expect("audit rows")
}

async fn group_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM groups")
        .fetch_one(pool)
        .await
        .expect("group count")
}

async fn group_audit_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM security_events WHERE event_type LIKE 'group.%'")
        .fetch_one(pool)
        .await
        .expect("audit count")
}

/// An application-role connection that FORGES every session setting a
/// privileged caller might be expected to carry: the principal is the group's
/// own admin, the group sets name the group, and the enforcement valve is off.
async fn forged_app_conn(
    pool: &PgPool,
    principal: Uuid,
    group: Uuid,
) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    use sqlx::Executor;
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade to the application role");
    sqlx::query(
        "SELECT set_config('epigraph.principal_id', $1, false), \
                set_config('epigraph.group_ids', $2, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.operator_link_enforcement', 'off', false)",
    )
    .bind(principal.to_string())
    .bind(group.to_string())
    .execute(&mut *conn)
    .await
    .expect("forge the session settings");
    conn
}

/// An application-role connection stamped with `principal` ONLY: no group
/// set, no writable set, the valve untouched. Only a policy arm keyed on the
/// principal itself (077's own-row and group-admin arms, 092's creator arm)
/// can admit what it does, which is exactly the case a lookup filtered by row
/// security would get wrong.
async fn stamped_app_conn(
    pool: &PgPool,
    principal: Uuid,
) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    use sqlx::Executor;
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade to the application role");
    sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
        .bind(principal.to_string())
        .execute(&mut *conn)
        .await
        .expect("stamp the principal");
    conn
}

/// Run one statement binding `(a, b)` on `conn`; the rows it changed.
async fn exec2(
    conn: &mut sqlx::PgConnection,
    sql: &str,
    a: Uuid,
    b: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(sql)
        .bind(a)
        .bind(b)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
}

/// Run one statement binding `a` on `conn`; the rows it changed.
async fn exec1(conn: &mut sqlx::PgConnection, sql: &str, a: Uuid) -> Result<u64, sqlx::Error> {
    sqlx::query(sql)
        .bind(a)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
}

/// The message of a refusal, for asserting WHICH control refused.
fn message_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> String {
    r.as_ref()
        .err()
        .and_then(|e| e.as_database_error().map(|d| d.message().to_string()))
        .unwrap_or_default()
}

/// A KEYED team group made through the APPLICATION path, in the REST create
/// route's shape: `creator`'s stamped session inserts the group (092's creator
/// arm) and its own admin row (the empty-roster bootstrap). Not verb-managed:
/// the positive control for every statement the verb-managed groups refuse.
async fn app_keyed_group(pool: &PgPool, creator: Uuid, name: &str) -> Uuid {
    let mut conn = stamped_app_conn(pool, creator).await;
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, 'did:key:probe-' || gen_random_uuid()::text, \
                 decode(repeat('ab', 32), 'hex'), 'team', $2) RETURNING id",
    )
    .bind(name)
    .bind(creator)
    .fetch_one(&mut *conn)
    .await
    .expect("the application path creates a keyed team group");
    exec2(
        &mut conn,
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
        group,
        creator,
    )
    .await
    .expect("the creator enrols itself as admin of an empty roster");
    reset(conn).await;
    group
}

async fn reset(mut conn: sqlx::pool::PoolConnection<sqlx::Postgres>) {
    use sqlx::Executor;
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset session authorization");
}

/// `(prosecdef, owner, proacl, proconfig)` of one function.
type CatalogRow = (bool, String, Option<String>, Option<Vec<String>>);

/// The four verbs are `SECURITY DEFINER`, owned by `epigraph_maintenance`,
/// with an explicit ACL naming the maintenance role and neither PUBLIC nor the
/// application role. Pinned in the catalog because the harness migrates as a
/// superuser: a silently no-opped `OWNER TO` would pass every behavioural test.
#[sqlx::test(migrations = "../../migrations")]
async fn the_verbs_are_maintenance_owned_definers_only_maintenance_executes(pool: PgPool) {
    for signature in [
        "public.epigraph_create_team_group(text, uuid, text)",
        "public.epigraph_team_group_add_member(uuid, uuid, text, text)",
        "public.epigraph_team_group_remove_member(uuid, uuid, text)",
        "public.epigraph_team_group_set_member_role(uuid, uuid, text, text)",
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
            acl.contains("epigraph_maintenance=X"),
            "{signature}: the maintenance role must hold EXECUTE: {acl}"
        );
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
}

/// The application role cannot call any verb, even stamped as the group's own
/// live admin with the group in both of its group sets and the enforcement
/// valve off; nothing is written and no audit row appears. The positive
/// control is the identical call on a maintenance session, which succeeds.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_execute_the_verbs_even_with_forged_session_settings(pool: PgPool) {
    let admin = human(&pool, "forge-admin").await;
    let other = human(&pool, "forge-other").await;
    let group = create(&pool, "forge probe team", admin)
        .await
        .expect("POSITIVE CONTROL: a maintenance session creates the group");
    let groups_before = group_count(&pool).await;
    let audit_before = group_audit_count(&pool).await;

    let mut conn = forged_app_conn(&pool, admin, group).await;
    let calls: [(&str, sqlx::query::Query<'_, sqlx::Postgres, _>); 4] = [
        (
            "create",
            sqlx::query("SELECT public.epigraph_create_team_group($1, $2, $3)")
                .bind("forged team")
                .bind(admin)
                .bind("forged"),
        ),
        (
            "add",
            sqlx::query("SELECT * FROM public.epigraph_team_group_add_member($1, $2, $3, $4)")
                .bind(group)
                .bind(other)
                .bind("writer")
                .bind("forged"),
        ),
        (
            "set-role",
            sqlx::query("SELECT * FROM public.epigraph_team_group_set_member_role($1, $2, $3, $4)")
                .bind(group)
                .bind(admin)
                .bind("reader")
                .bind("forged"),
        ),
        (
            "remove",
            sqlx::query("SELECT * FROM public.epigraph_team_group_remove_member($1, $2, $3)")
                .bind(group)
                .bind(admin)
                .bind("forged"),
        ),
    ];
    for (what, q) in calls {
        let r = q.execute(&mut *conn).await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "{what} on a forged application session must be refused 42501: {r:?}"
        );
        assert!(
            message_of(&r).contains("permission denied for function"),
            "{what}: refused by the ACL, before the body runs: {r:?}"
        );
    }
    reset(conn).await;

    assert_eq!(
        group_count(&pool).await,
        groups_before,
        "no group was created"
    );
    assert_eq!(
        group_audit_count(&pool).await,
        audit_before,
        "no audit row was written"
    );
    assert_eq!(
        live_role(&pool, group, admin).await.as_deref(),
        Some("admin")
    );
    assert_eq!(live_role(&pool, group, other).await, None);

    // POSITIVE CONTROL: the same add on a maintenance session.
    let ok = add(&pool, group, other, "writer")
        .await
        .expect("the maintenance session adds the member");
    assert!(ok.applied, "{ok:?}");
    assert_eq!(
        live_role(&pool, group, other).await.as_deref(),
        Some("writer")
    );
}

/// The `group.` audit family is reserved: the application role cannot insert
/// a row that looks like a roster act, while it still writes an ordinary
/// security event.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_forge_a_group_audit_row(pool: PgPool) {
    let admin = human(&pool, "audit-forge").await;
    let mut conn = forged_app_conn(&pool, admin, Uuid::new_v4()).await;
    let forged = sqlx::query(
        "INSERT INTO security_events (event_type, agent_id, success, details) \
         VALUES ('group.member_added', $1, true, '{}'::jsonb)",
    )
    .bind(admin)
    .execute(&mut *conn)
    .await;
    assert_eq!(
        code_of(&forged).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "a forged group.* audit row must be refused: {forged:?}"
    );
    let ordinary = sqlx::query(
        "INSERT INTO security_events (event_type, agent_id, success, details) \
         VALUES ('probe.ordinary_event', $1, true, '{}'::jsonb)",
    )
    .bind(admin)
    .execute(&mut *conn)
    .await;
    reset(conn).await;
    ordinary.expect("POSITIVE CONTROL: an unreserved event type is still app-writable");
}

/// Create, add, set-role and remove on a maintenance session: each does what
/// it says, the group is keyless, and each writes exactly one audit row naming
/// the group, the member, the roles and the reason.
#[sqlx::test(migrations = "../../migrations")]
async fn create_add_set_role_and_remove_work_on_maintenance_and_each_is_audited(pool: PgPool) {
    let admin = human(&pool, "lifecycle-admin").await;
    let member = human(&pool, "lifecycle-member").await;

    let group = create(&pool, "Synthetic Research Team", admin)
        .await
        .expect("create");
    let (kind, did_key, key_len, creator, status): (String, String, i32, Option<Uuid>, String) =
        sqlx::query_as(
            "SELECT kind::text, did_key, octet_length(public_key), created_by_agent_id, \
                    status::text FROM groups WHERE id = $1",
        )
        .bind(group)
        .fetch_one(&pool)
        .await
        .expect("the group row");
    assert_eq!(kind, "team");
    assert_eq!(did_key, format!("did:epigraph:group:{group}"));
    assert_eq!(key_len, 0, "a keyless team group carries no key material");
    assert_eq!(creator, Some(admin), "the admin Person is the creator");
    assert_eq!(status, "active");
    let epochs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM group_key_epochs WHERE group_id = $1")
            .bind(group)
            .fetch_one(&pool)
            .await
            .expect("epochs");
    assert_eq!(epochs, 0, "no key epoch is written for a keyless group");
    let (share, epoch): (Vec<u8>, i32) = sqlx::query_as(
        "SELECT wrapped_key_share, epoch FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(admin)
    .fetch_one(&pool)
    .await
    .expect("the admin row");
    assert!(share.is_empty(), "the admin's share is empty");
    assert_eq!(epoch, 0);
    assert_eq!(
        live_role(&pool, group, admin).await.as_deref(),
        Some("admin")
    );

    let added = add(&pool, group, member, "writer").await.expect("add");
    assert!(added.applied && added.membership.is_some(), "{added:?}");
    assert_eq!(
        live_role(&pool, group, member).await.as_deref(),
        Some("writer")
    );

    // Idempotent: the same add again writes nothing and no audit row.
    let again = add(&pool, group, member, "writer").await.expect("re-add");
    assert!(!again.applied, "{again:?}");
    assert_eq!(again.membership, added.membership);

    let set = set_role(&pool, group, member, "reader")
        .await
        .expect("set-role");
    assert!(set.applied, "{set:?}");
    assert_eq!(set.prior_role.as_deref(), Some("writer"));
    assert_eq!(
        set.membership, added.membership,
        "set-role changes the live row"
    );
    assert_eq!(
        live_role(&pool, group, member).await.as_deref(),
        Some("reader")
    );

    let removed = remove(&pool, group, member).await.expect("remove");
    assert!(removed.applied, "{removed:?}");
    assert_eq!(removed.prior_role.as_deref(), Some("reader"));
    assert_eq!(live_role(&pool, group, member).await, None);

    let events = audit(&pool, group).await;
    let kinds: Vec<&str> = events.iter().map(|(k, _, _)| k.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "group.team_created",
            "group.member_added",
            "group.member_role_set",
            "group.member_removed"
        ],
        "one audit row per act, none for the no-op re-add: {events:?}"
    );
    let (_, created_agent, created) = &events[0];
    assert_eq!(*created_agent, Some(admin));
    assert_eq!(created["admin"], admin.to_string());
    assert_eq!(created["display_name"], "Synthetic Research Team");
    assert_eq!(created["reason"], "team group verb test");
    for (kind, agent, d) in &events[1..] {
        assert_eq!(*agent, Some(member), "{kind} names the member");
        assert_eq!(d["member"], member.to_string(), "{kind}: {d}");
        assert_eq!(d["reason"], "team group verb test", "{kind}: {d}");
        assert!(d["session_user"].is_string(), "{kind}: {d}");
        assert!(
            d["actor"].is_null(),
            "{kind}: a direct SQL call states no process context: {d}"
        );
    }
    assert_eq!(events[1].2["role"], "writer");
    assert_eq!(events[2].2["prior_role"], "writer");
    assert_eq!(events[2].2["role"], "reader");
    assert_eq!(events[3].2["prior_role"], "reader");
}

/// The admin must be a REGISTERED human operator: an agent with no registry
/// row, and a human whose recorded human client was suspended, are refused and
/// nothing is written. A team name already in use by an active team group is
/// refused too, so a re-run cannot mint a second group.
#[sqlx::test(migrations = "../../migrations")]
async fn create_requires_a_registered_human_admin_and_a_free_name(pool: PgPool) {
    let (plain, _) = fixture::seed_agent_with_group(&pool, "not-a-human").await;
    let suspended = human(&pool, "suspended-human").await;
    sqlx::query("UPDATE oauth_clients SET status = 'suspended' WHERE agent_id = $1")
        .bind(suspended)
        .execute(&pool)
        .await
        .expect("suspend the human client");
    let groups_before = group_count(&pool).await;
    for (who, what) in [
        (plain, "an unregistered agent"),
        (suspended, "a suspended human"),
    ] {
        let r = create(&pool, "Synthetic Refused Team", who).await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(NOT_A_HUMAN_ADMIN),
            "{what} as admin: {r:?}"
        );
    }
    assert_eq!(
        group_count(&pool).await,
        groups_before,
        "nothing was created"
    );
    assert_eq!(group_audit_count(&pool).await, 0, "no audit row");

    // POSITIVE CONTROL: a registered human creates the group.
    let ok = human(&pool, "registered-human").await;
    create(&pool, "Synthetic Refused Team", ok)
        .await
        .expect("a registered human admin is admitted");

    // The same name again (case and padding aside) is refused.
    let dup = create(&pool, "  synthetic refused TEAM ", ok).await;
    assert_eq!(code_of(&dup).as_deref(), Some(DUPLICATE_NAME), "{dup:?}");
    let named: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM groups \
          WHERE kind = 'team' AND lower(btrim(display_name)) = 'synthetic refused team'",
    )
    .fetch_one(&pool)
    .await
    .expect("named team groups");
    assert_eq!(named, 1, "the duplicate created nothing");
}

/// The last live admin can be neither removed nor demoted. With a second live
/// admin, the first is removable, and then the second is the last.
#[sqlx::test(migrations = "../../migrations")]
async fn the_last_live_admin_can_be_neither_removed_nor_demoted(pool: PgPool) {
    let first = human(&pool, "last-admin-first").await;
    let second = human(&pool, "last-admin-second").await;
    let group = create(&pool, "Synthetic Admin Team", first)
        .await
        .expect("create");

    let r = remove(&pool, group, first).await;
    assert_eq!(code_of(&r).as_deref(), Some(LAST_ADMIN), "remove: {r:?}");
    for role in ["writer", "reader"] {
        let r = set_role(&pool, group, first, role).await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(LAST_ADMIN),
            "demote to {role}: {r:?}"
        );
    }
    assert_eq!(
        live_role(&pool, group, first).await.as_deref(),
        Some("admin")
    );
    assert_eq!(
        audit(&pool, group).await.len(),
        1,
        "only the creation is audited"
    );

    // POSITIVE CONTROL: a second live admin makes the first removable.
    add(&pool, group, second, "admin")
        .await
        .expect("second admin");
    let ok = remove(&pool, group, first)
        .await
        .expect("remove the first admin");
    assert!(
        ok.applied && ok.prior_role.as_deref() == Some("admin"),
        "{ok:?}"
    );

    // Now the second is the last.
    let r = remove(&pool, group, second).await;
    assert_eq!(code_of(&r).as_deref(), Some(LAST_ADMIN), "{r:?}");
    let r = set_role(&pool, group, second, "writer").await;
    assert_eq!(code_of(&r).as_deref(), Some(LAST_ADMIN), "{r:?}");
    assert_eq!(
        live_role(&pool, group, second).await.as_deref(),
        Some("admin")
    );
}

/// The scope rule, checked on two groups: one before the database is armed and
/// one after, because the verb holds it in both states (a maintenance session
/// is exempt from 122's membership trigger, so the verb is the only control).
///
/// * an operated agent is refused at ANY role while its operator does not
///   write the group (not a member, or only a reader), and admitted as reader
///   or writer once the operator writes it;
/// * an operated agent is never an admin (admins are humans);
/// * an unbound agent and a retired-linked agent are never members;
/// * the operator cannot be removed, nor demoted to reader, while its agent is
///   a live member; it can once the agent is removed.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_is_a_member_only_where_its_operator_writes(pool: PgPool) {
    let owner = human(&pool, "scope-owner").await;
    let operator = human(&pool, "scope-operator").await;
    let agent = operated(&pool, operator, "scope-agent").await;
    let gone = retired(&pool, operator, "scope-retired").await;
    let (unbound, _) = fixture::seed_agent_with_group(&pool, "scope-unbound").await;

    for (phase, armed) in [("unarmed", false), ("armed", true)] {
        if armed {
            arm(&pool).await;
        }
        let group = create(&pool, &format!("Synthetic Scope Team {phase}"), owner)
            .await
            .expect("create");

        // The operator is not a member: the agent is refused at every role.
        for role in ["reader", "writer"] {
            let r = add(&pool, group, agent, role).await;
            assert_eq!(
                code_of(&r).as_deref(),
                Some(OPERATOR_SCOPE),
                "{phase}: agent as {role} with a non-member operator: {r:?}"
            );
        }
        // The operator only READS the group: still refused.
        add(&pool, group, operator, "reader")
            .await
            .expect("operator reader");
        let r = add(&pool, group, agent, "reader").await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(OPERATOR_SCOPE),
            "{phase}: agent with a reader operator: {r:?}"
        );
        // Unbound and retired-linked agents are never members.
        for (who, what) in [(unbound, "unbound"), (gone, "retired-linked")] {
            let r = add(&pool, group, who, "reader").await;
            assert_eq!(
                code_of(&r).as_deref(),
                Some(NOT_BOUND),
                "{phase}: {what}: {r:?}"
            );
        }
        assert_eq!(live_role(&pool, group, agent).await, None);

        // POSITIVE CONTROL: once the operator writes the group, the agent is
        // admitted as writer (and as reader via set-role).
        set_role(&pool, group, operator, "writer")
            .await
            .expect("operator writer");
        // Never an admin by add, even where its operator writes (the one
        // state in which every other add rule would admit it).
        let r = add(&pool, group, agent, "admin").await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(NOT_A_HUMAN_ADMIN),
            "{phase}: an operated agent added as admin: {r:?}"
        );
        assert_eq!(live_role(&pool, group, agent).await, None, "{phase}");
        add(&pool, group, agent, "writer")
            .await
            .expect("the agent is admitted where its operator writes");
        set_role(&pool, group, agent, "reader")
            .await
            .expect("the agent may be demoted to reader");
        // Nor by set-role.
        let r = set_role(&pool, group, agent, "admin").await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(NOT_A_HUMAN_ADMIN),
            "{phase}: {r:?}"
        );

        // The operator cannot leave its agent stranded.
        let r = remove(&pool, group, operator).await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(OPERATOR_SCOPE),
            "{phase}: {r:?}"
        );
        let r = set_role(&pool, group, operator, "reader").await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(OPERATOR_SCOPE),
            "{phase}: {r:?}"
        );
        assert_eq!(
            live_role(&pool, group, operator).await.as_deref(),
            Some("writer")
        );

        // POSITIVE CONTROL: with the agent removed, the operator can go.
        remove(&pool, group, agent).await.expect("remove the agent");
        remove(&pool, group, operator)
            .await
            .expect("the operator is removable once its agent is gone");
    }
}

/// A removal is a REVOKE: the row stays with `revoked_at` set. The member's
/// `Viewer::resolve` stops returning the group, and its stamped application
/// session stops reading the group's claim (row security, not the in-query
/// predicate). A re-add writes a NEW row at the next epoch, leaving the
/// revoked one in place.
#[sqlx::test(migrations = "../../migrations")]
async fn removal_is_a_revoke_and_the_viewer_stops_seeing_the_group(pool: PgPool) {
    let admin = human(&pool, "revoke-admin").await;
    let member = human(&pool, "revoke-member").await;
    let group = create(&pool, "Synthetic Revoke Team", admin)
        .await
        .expect("create");
    add(&pool, group, member, "writer").await.expect("add");
    let claim = fixture::seed_group_claim(&pool, admin, group, "revoke probe claim").await;

    let sees = |pool: PgPool| async move {
        let viewer = Viewer::resolve(&pool, member).await.expect("resolve");
        let in_set = viewer.group_bind().is_some_and(|g| g.contains(&group));
        let groups: Vec<String> = viewer
            .group_bind()
            .unwrap_or_default()
            .iter()
            .map(Uuid::to_string)
            .collect();
        let writable: Vec<String> = viewer
            .writable_groups()
            .iter()
            .map(Uuid::to_string)
            .collect();
        use sqlx::Executor;
        let mut conn = pool.acquire().await.expect("acquire");
        conn.execute("SET SESSION AUTHORIZATION epigraph_app")
            .await
            .expect("downgrade");
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $3, false)",
        )
        .bind(member.to_string())
        .bind(groups.join(","))
        .bind(writable.join(","))
        .execute(&mut *conn)
        .await
        .expect("stamp as the viewer");
        let reads: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&mut *conn)
            .await
            .expect("stamped read");
        conn.execute("RESET SESSION AUTHORIZATION")
            .await
            .expect("reset");
        (in_set, reads)
    };

    assert_eq!(
        sees(pool.clone()).await,
        (true, 1),
        "POSITIVE CONTROL: a live member resolves the group and reads its claim"
    );

    let removed = remove(&pool, group, member).await.expect("remove");
    assert!(removed.applied, "{removed:?}");
    assert_eq!(
        rows(&pool, group, member).await,
        [(0, "writer".to_string(), true)],
        "the row is kept, revoked"
    );
    assert_eq!(
        sees(pool.clone()).await,
        (false, 0),
        "a removed member's re-resolved viewer neither carries the group nor, stamped from \
         it, reads the group's claim"
    );
    // RECORDED LIMITATION, pinned so a change shows: row security reads the
    // SESSION's group set, so a session stamped BEFORE the removal (a cached
    // viewer, a long-lived connection) still reads the group's claim until it
    // re-resolves. The revoke takes effect at the next resolve, not at the
    // database.
    let mut stale = forged_app_conn(&pool, member, group).await;
    let stale_reads: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&mut *stale)
        .await
        .expect("stale read");
    reset(stale).await;
    assert_eq!(
        stale_reads, 1,
        "a session stamped with the pre-removal group set still reads (limitation)"
    );

    // Removing again is a no-op, not a second revoke.
    let again = remove(&pool, group, member).await.expect("remove again");
    assert!(!again.applied && again.membership.is_none(), "{again:?}");

    // A re-add is a new row; the revoked one stays.
    let readd = add(&pool, group, member, "reader").await.expect("re-add");
    assert!(readd.applied, "{readd:?}");
    assert_ne!(
        readd.membership, removed.membership,
        "a new row, not a revival"
    );
    assert_eq!(
        rows(&pool, group, member).await,
        [
            (0, "writer".to_string(), true),
            (1, "reader".to_string(), false)
        ],
        "the ledger keeps the revoked row and adds a live one"
    );
    assert_eq!(sees(pool.clone()).await, (true, 1));
}

/// The words of 164's roster guard, so a refusal is attributed to IT and not
/// to row security or another trigger that happens to share the SQLSTATE.
const ROSTER_GUARD: &str = "only by the team-group verbs";

/// Migration 092's group-creation arm on a verb-created group. Its READ half
/// is bounded by the roster: the creator's stamped application session reads
/// the group row while it is a live member and loses it once removed (another
/// admin remains), so the arm keyed on `created_by_agent_id` does not outlive
/// the membership. Its WRITE half never reaches a verb-managed roster: the
/// creator's stamped insert is refused by 164's roster guard (named by its
/// message, not just its SQLSTATE) both while it is a live member and after.
/// The positive control is the identical insert by the same creator into a
/// keyed group it made through the application path, which lands.
#[sqlx::test(migrations = "../../migrations")]
async fn the_creator_arm_reads_only_while_a_member_and_never_writes_a_managed_roster(pool: PgPool) {
    let creator = human(&pool, "arm-creator").await;
    let successor = human(&pool, "arm-successor").await;
    let group = create(&pool, "Synthetic Arm Team", creator)
        .await
        .expect("create");
    let keyed = app_keyed_group(&pool, creator, "arm keyed control").await;
    let enrol =
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
                 VALUES ($1, $2, ''::bytea, 7, 'reader')";

    let probe_live = human(&pool, "arm-probe-live").await;
    let probe_gone = human(&pool, "arm-probe-gone").await;
    let attempt = |pool: PgPool, probe: Uuid| async move {
        let mut conn = stamped_app_conn(&pool, creator).await;
        let seen = exec1(&mut conn, "SELECT 1 FROM groups WHERE id = $1", group)
            .await
            .expect("groups read");
        let inserted = exec2(&mut conn, enrol, group, probe).await;
        reset(conn).await;
        (seen, inserted)
    };

    let (seen, inserted) = attempt(pool.clone(), probe_live).await;
    assert_eq!(seen, 1, "POSITIVE CONTROL: the live creator sees its group");
    assert_eq!(
        code_of(&inserted).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "the live creator's stamped insert into a verb-managed roster: {inserted:?}"
    );
    assert!(
        message_of(&inserted).contains(ROSTER_GUARD),
        "refused by the roster guard: {inserted:?}"
    );

    // POSITIVE CONTROL: the identical insert into the creator's keyed group.
    let mut conn = stamped_app_conn(&pool, creator).await;
    let control = exec2(&mut conn, enrol, keyed, probe_live).await;
    reset(conn).await;
    assert_eq!(
        control.expect("the insert shape lands on a keyed group"),
        1,
        "the creator enrols through 092's arm where the verbs do not manage the roster"
    );

    add(&pool, group, successor, "admin")
        .await
        .expect("successor admin");
    remove(&pool, group, creator)
        .await
        .expect("remove the creator");

    let (seen, inserted) = attempt(pool.clone(), probe_gone).await;
    assert_eq!(
        seen, 0,
        "a removed creator no longer sees the group through 092's arm"
    );
    assert_eq!(
        code_of(&inserted).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "{inserted:?}"
    );
    assert!(message_of(&inserted).contains(ROSTER_GUARD), "{inserted:?}");
    assert_eq!(live_role(&pool, group, probe_live).await, None);
    assert_eq!(live_role(&pool, group, probe_gone).await, None);
    assert_eq!(
        live_role(&pool, group, successor).await.as_deref(),
        Some("admin")
    );
}

/// A verb-managed roster has ONE writer, the verbs. An application session
/// stamped as the group's own live admin and creator (the strongest stamp a
/// holder of the application DSN can forge) cannot add an operated agent as a
/// reader (122 is quiet for reader rows), cannot add that agent's operator as
/// a writer (122 is quiet for a human), cannot demote itself and cannot revoke
/// a row (the REST remove route's statement). Nothing changes and no audit row
/// appears. The positive control is the same principal enrolling the same
/// agent, and revoking it, in a keyed group it made through the application
/// path.
#[sqlx::test(migrations = "../../migrations")]
async fn the_application_path_cannot_write_a_verb_managed_roster(pool: PgPool) {
    let admin = human(&pool, "roster-admin").await;
    let operator = human(&pool, "roster-operator").await;
    let agent = operated(&pool, operator, "roster-agent").await;
    let group = create(&pool, "Synthetic Roster Team", admin)
        .await
        .expect("create");
    let keyed = app_keyed_group(&pool, admin, "roster keyed control").await;
    let audit_before = audit(&pool, group).await.len();

    let insert_reader = "INSERT INTO group_memberships \
                           (group_id, agent_id, wrapped_key_share, epoch, role) \
                         VALUES ($1, $2, ''::bytea, 9, 'reader')";
    let insert_writer = "INSERT INTO group_memberships \
                           (group_id, agent_id, wrapped_key_share, epoch, role) \
                         VALUES ($1, $2, ''::bytea, 9, 'writer')";
    let demote = "UPDATE group_memberships SET role = 'reader' \
                   WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL";
    let revoke = "UPDATE group_memberships SET revoked_at = now() \
                   WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL";

    let mut conn = stamped_app_conn(&pool, admin).await;
    let attempts = [
        (
            "an operated agent as reader",
            exec2(&mut conn, insert_reader, group, agent).await,
        ),
        (
            "its operator as writer",
            exec2(&mut conn, insert_writer, group, operator).await,
        ),
        (
            "the admin demoting itself",
            exec2(&mut conn, demote, group, admin).await,
        ),
        (
            "the admin revoking its own row",
            exec2(&mut conn, revoke, group, admin).await,
        ),
    ];
    // POSITIVE CONTROL: the same principal, the same statements, a keyed group.
    let control_add = exec2(&mut conn, insert_reader, keyed, agent).await;
    let control_revoke = exec2(&mut conn, revoke, keyed, agent).await;
    reset(conn).await;

    for (what, r) in &attempts {
        assert_eq!(
            code_of(r).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "{what}: {r:?}"
        );
        assert!(message_of(r).contains(ROSTER_GUARD), "{what}: {r:?}");
    }
    assert_eq!(live_role(&pool, group, agent).await, None);
    assert_eq!(live_role(&pool, group, operator).await, None);
    assert_eq!(
        live_role(&pool, group, admin).await.as_deref(),
        Some("admin")
    );
    assert_eq!(
        audit(&pool, group).await.len(),
        audit_before,
        "no audit row"
    );

    assert_eq!(control_add.expect("keyed: enrol"), 1, "keyed: enrol");
    assert_eq!(control_revoke.expect("keyed: revoke"), 1, "keyed: revoke");
}

/// A creator DEMOTED by set-role stays demoted: its stamped application
/// session can neither promote its own row back to admin (092's creator arm
/// would admit that on any other group) nor rewrite the group row (`public_key`,
/// `status`, `display_name`), any of which would take the group out of the
/// verbs' hands (GRP05) or rename it under the audit trail. The verbs still
/// manage the group afterwards. The positive control is the same four
/// statements by a creator demoted the same way in a keyed group made through
/// the application path, each of which changes one row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_demoted_creator_cannot_restore_itself_or_change_the_group_row(pool: PgPool) {
    let creator = human(&pool, "demote-creator").await;
    let second = human(&pool, "demote-second").await;
    let late = human(&pool, "demote-late").await;
    let name = "Synthetic Demotion Team";
    let group = create(&pool, name, creator).await.expect("create");
    add(&pool, group, second, "admin")
        .await
        .expect("second admin");
    let demoted = set_role(&pool, group, creator, "reader")
        .await
        .expect("demote the creator");
    assert!(demoted.applied, "{demoted:?}");

    let promote = "UPDATE group_memberships SET role = 'admin' \
                    WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL";
    let rekey = "UPDATE groups SET public_key = decode(repeat('cd', 32), 'hex') WHERE id = $1";
    let suspend = "UPDATE groups SET status = 'suspended' WHERE id = $1";
    let rename = "UPDATE groups SET display_name = 'renamed on the app path' WHERE id = $1";

    let mut conn = stamped_app_conn(&pool, creator).await;
    let attempts = [
        (
            "self-promotion",
            exec2(&mut conn, promote, group, creator).await,
        ),
        ("re-key", exec1(&mut conn, rekey, group).await),
        ("suspend", exec1(&mut conn, suspend, group).await),
        ("rename", exec1(&mut conn, rename, group).await),
    ];
    reset(conn).await;
    for (what, r) in &attempts {
        assert_eq!(
            code_of(r).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "{what}: {r:?}"
        );
    }
    assert_eq!(
        live_role(&pool, group, creator).await.as_deref(),
        Some("reader")
    );
    let row: (i32, String, String) = sqlx::query_as(
        "SELECT octet_length(public_key), status::text, display_name FROM groups WHERE id = $1",
    )
    .bind(group)
    .fetch_one(&pool)
    .await
    .expect("the group row");
    assert_eq!(row, (0, "active".to_string(), name.to_string()));
    add(&pool, group, late, "reader")
        .await
        .expect("the verbs still manage the group");

    // POSITIVE CONTROL: a keyed group, the same creator, demoted the same way
    // (a second admin first, then its own row to reader), the same statements.
    let keyed = app_keyed_group(&pool, creator, "demotion keyed control").await;
    let mut conn = stamped_app_conn(&pool, creator).await;
    let insert_admin = "INSERT INTO group_memberships \
                          (group_id, agent_id, wrapped_key_share, epoch, role) \
                        VALUES ($1, $2, ''::bytea, 0, 'admin')";
    let demote = "UPDATE group_memberships SET role = 'reader' \
                   WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL";
    let setup = [
        exec2(&mut conn, insert_admin, keyed, second).await,
        exec2(&mut conn, demote, keyed, creator).await,
    ];
    let controls = [
        (
            "self-promotion",
            exec2(&mut conn, promote, keyed, creator).await,
        ),
        ("re-key", exec1(&mut conn, rekey, keyed).await),
        ("suspend", exec1(&mut conn, suspend, keyed).await),
        ("rename", exec1(&mut conn, rename, keyed).await),
    ];
    reset(conn).await;
    for r in setup {
        assert_eq!(r.expect("keyed control setup"), 1);
    }
    for (what, r) in controls {
        assert_eq!(
            r.unwrap_or_else(|e| panic!("keyed {what}: {e}")),
            1,
            "keyed {what}"
        );
    }
}

/// The application path cannot mint a group the verbs would manage: neither a
/// keyless team group (the relaxed CHECK admits one) nor any group in the
/// verbs' `did:epigraph:group:` namespace, while a keyed team group is still
/// app-creatable (the REST create route). And a team NAME is held only by a
/// verb-made group: a keyed group of the same name does not refuse `create`,
/// while a second verb-made one is refused with GRP06 naming the first.
#[sqlx::test(migrations = "../../migrations")]
async fn the_application_path_cannot_mint_a_group_the_verbs_would_manage(pool: PgPool) {
    let (minter, _) = fixture::seed_agent_with_group(&pool, "mint-agent").await;
    let admin = human(&pool, "mint-admin").await;
    let name = "Synthetic Squat Team";
    let insert = |did: &'static str, key: &'static str| {
        format!(
            "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
             VALUES ('{name}', {did} || gen_random_uuid()::text, {key}, 'team', $1)"
        )
    };
    let keyless_sql = insert("'did:key:probe-'", "''::bytea");
    let namespaced_sql = insert("'did:epigraph:group:'", "decode(repeat('ab', 32), 'hex')");
    let keyed_sql = insert("'did:key:probe-'", "decode(repeat('ab', 32), 'hex')");

    let mut conn = stamped_app_conn(&pool, minter).await;
    let keyless = exec1(&mut conn, &keyless_sql, minter).await;
    let namespaced = exec1(&mut conn, &namespaced_sql, minter).await;
    let keyed = exec1(&mut conn, &keyed_sql, minter).await;
    reset(conn).await;

    for (what, r) in [("keyless", &keyless), ("namespaced", &namespaced)] {
        assert_eq!(
            code_of(r).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "an app-minted {what} team group: {r:?}"
        );
    }
    assert_eq!(
        keyed.expect("POSITIVE CONTROL: a keyed team group is app-creatable"),
        1
    );
    let minted: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM groups WHERE created_by_agent_id = $1 AND kind = 'team'",
    )
    .bind(minter)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(minted, 1, "only the keyed control was created");

    let first = create(&pool, name, admin)
        .await
        .expect("a keyed group of the same name does not hold the name");
    let dup = create(&pool, "  synthetic squat TEAM", admin).await;
    assert_eq!(code_of(&dup).as_deref(), Some(DUPLICATE_NAME), "{dup:?}");
    assert!(
        message_of(&dup).contains(&first.to_string()),
        "GRP06 names the group that holds the name: {dup:?}"
    );
}

/// The member verbs act only on ACTIVE, verb-made team groups. Every other
/// group is refused with GRP05 by add, remove AND set-role, each with a live
/// member row present so remove and set-role reach the guard, and nothing is
/// written: a personal group (107's link path), the world and seed groups, a
/// community group, a keyed team group, a keyless team group outside the
/// verbs' `did:epigraph:group:` namespace, and a verb-made group that is
/// suspended or deprovisioned. The positive control is the same three verbs on
/// an active verb-made group.
#[sqlx::test(migrations = "../../migrations")]
async fn the_member_verbs_refuse_every_group_they_do_not_manage(pool: PgPool) {
    const NOT_MANAGED: &str = "GRP05";
    let admin = human(&pool, "kind-admin").await;
    let member = human(&pool, "kind-member").await;
    let newcomer = human(&pool, "kind-newcomer").await;
    let personal: Uuid = sqlx::query_scalar(
        "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text",
    )
    .bind(admin)
    .fetch_one(&pool)
    .await
    .expect("personal group");
    let raw_group = |did: &'static str, key: &'static str, kind: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(&format!(
                "INSERT INTO groups (display_name, did_key, public_key, kind, \
                                     created_by_agent_id) \
                 VALUES ('{kind} probe', {did} || gen_random_uuid()::text, {key}, '{kind}', $1) \
                 RETURNING id"
            ))
            .bind(admin)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("{kind} probe group: {e}"))
        }
    };
    let community = raw_group("'did:epigraph:community:'", "''::bytea", "community").await;
    let keyed = raw_group(
        "'did:key:probe-'",
        "decode(repeat('ab', 32), 'hex')",
        "team",
    )
    .await;
    let keyless_outside = raw_group("'did:key:probe-'", "''::bytea", "team").await;
    let mut parked = Vec::new();
    for status in ["suspended", "deprovisioned"] {
        let g = create(&pool, &format!("Synthetic Parked Team {status}"), admin)
            .await
            .expect("create");
        sqlx::query("UPDATE groups SET status = $2 WHERE id = $1")
            .bind(g)
            .bind(status)
            .execute(&pool)
            .await
            .expect("park the group");
        parked.push((g, status));
    }

    let mut refused = vec![
        (personal, "personal"),
        (fixture::world_group(&pool).await, "world"),
        (fixture::seed_group(&pool).await, "seed"),
        (community, "community"),
        (keyed, "keyed team"),
        (keyless_outside, "keyless team outside the verbs' namespace"),
    ];
    refused.extend(parked);
    for (g, what) in &refused {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'reader')",
        )
        .bind(g)
        .bind(member)
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("{what}: seed a live member row: {e}"));
    }

    let audit_before = group_audit_count(&pool).await;
    for (g, what) in refused {
        let r = add(&pool, g, newcomer, "reader").await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(NOT_MANAGED),
            "{what}: add: {r:?}"
        );
        let r = remove(&pool, g, member).await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(NOT_MANAGED),
            "{what}: remove: {r:?}"
        );
        let r = set_role(&pool, g, member, "writer").await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(NOT_MANAGED),
            "{what}: set-role: {r:?}"
        );
        assert_eq!(live_role(&pool, g, newcomer).await, None, "{what}");
        assert_eq!(
            live_role(&pool, g, member).await.as_deref(),
            Some("reader"),
            "{what}"
        );
    }
    assert_eq!(group_audit_count(&pool).await, audit_before, "no audit row");

    // POSITIVE CONTROL: an active verb-made group takes all three.
    let group = create(&pool, "Synthetic Kind Team", admin)
        .await
        .expect("create");
    assert!(
        add(&pool, group, member, "reader")
            .await
            .expect("add")
            .applied
    );
    assert!(
        set_role(&pool, group, member, "writer")
            .await
            .expect("set-role")
            .applied
    );
    assert!(remove(&pool, group, member).await.expect("remove").applied);
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

/// A fresh agent bound to `operator` by a migration-149 client ALLOWANCE (an
/// active service client for the agent, allowed by the maintenance role), with
/// no operator link. Returns `(agent, client)`.
async fn allowance_bound(pool: &PgPool, operator: Uuid, label: &str) -> (Uuid, Uuid) {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'team group allowance fixture', 'service', ARRAY['claims:write'], \
                 'active', $2, 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("team-group-allowance-{}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("service client");
    let mut c = maint(pool).await;
    sqlx::query("SELECT allowed_now FROM public.epigraph_allow_author_binding_client($1, $2, $3)")
        .bind(client)
        .bind(operator)
        .bind("team group verb test")
        .fetch_one(&mut *c)
        .await
        .expect("allow the client for the operator");
    reset(c).await;
    (agent, client)
}

/// A membership in a verb-made group lasts only as long as the binding that
/// admitted it. An agent bound to its operator by a 149 client allowance is
/// refused (GRP03) until the operator writes the group, then admitted, and
/// its viewer carries the group. Once the allowance is revoked the agent
/// belongs to no live human: its viewer no longer carries the group (the row
/// is still live; nothing else ended it), a promotion is refused with GRP04,
/// and the operator can still clean the row up with `remove`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_membership_lapses_with_the_allowance_that_admitted_it(pool: PgPool) {
    let owner = human(&pool, "lapse-owner").await;
    let operator = human(&pool, "lapse-operator").await;
    let (agent, client) = allowance_bound(&pool, operator, "lapse-service").await;
    let group = create(&pool, "Synthetic Allowance Team", owner)
        .await
        .expect("create");

    let r = add(&pool, group, agent, "reader").await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some(OPERATOR_SCOPE),
        "an allowance-bound agent whose operator does not write the group: {r:?}"
    );
    add(&pool, group, operator, "writer")
        .await
        .expect("operator writer");
    add(&pool, group, agent, "reader")
        .await
        .expect("POSITIVE CONTROL: admitted where its operator writes");
    assert_eq!(resolves(&pool, agent, group).await, (true, false));

    let mut c = maint(&pool).await;
    let revoked: bool = sqlx::query_scalar(
        "SELECT revoked_now FROM public.epigraph_revoke_author_binding_client($1, $2)",
    )
    .bind(client)
    .bind("team group verb test")
    .fetch_one(&mut *c)
    .await
    .expect("revoke the allowance");
    reset(c).await;
    assert!(revoked, "PREMISE: the allowance was live");

    assert_eq!(
        resolves(&pool, agent, group).await,
        (false, false),
        "a member whose binding lapsed no longer reads the group"
    );
    assert_eq!(
        live_role(&pool, group, agent).await.as_deref(),
        Some("reader"),
        "the row itself is untouched (the lapse is read, not written)"
    );
    let r = set_role(&pool, group, agent, "writer").await;
    assert_eq!(code_of(&r).as_deref(), Some(NOT_BOUND), "promotion: {r:?}");
    assert_eq!(
        resolves(&pool, operator, group).await,
        (true, true),
        "the operator, still registered, is unaffected"
    );
    let gone = remove(&pool, group, agent)
        .await
        .expect("remove the lapsed row");
    assert!(gone.applied, "{gone:?}");
}

/// When a human's REGISTRATION is revoked, the human and every agent it
/// operates stop carrying a verb-made group in their viewers, while the
/// human's personal group (107's path, not the verbs') still resolves. A
/// further agent of that human is refused (GRP04), the human cannot be made
/// an admin (GRP04), and the group's other admin is unaffected.
#[sqlx::test(migrations = "../../migrations")]
async fn a_membership_lapses_when_the_human_is_revoked(pool: PgPool) {
    let owner = human(&pool, "revoked-owner").await;
    let (operator, personal) = fixture::seed_human_operator(&pool, "revoked-operator").await;
    let agent = operated(&pool, operator, "revoked-agent").await;
    let later = operated(&pool, operator, "revoked-later").await;
    let group = create(&pool, "Synthetic Revoked Team", owner)
        .await
        .expect("create");
    add(&pool, group, operator, "writer")
        .await
        .expect("operator");
    add(&pool, group, agent, "writer").await.expect("agent");
    assert_eq!(resolves(&pool, operator, group).await, (true, true));
    assert_eq!(resolves(&pool, agent, group).await, (true, true));

    let mut c = maint(&pool).await;
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_now FROM public.epigraph_revoke_human_operator($1, $2)")
            .bind(operator)
            .bind("team group verb test")
            .fetch_one(&mut *c)
            .await
            .expect("revoke the registration");
    reset(c).await;
    assert!(revoked, "PREMISE: the registration was live");

    assert_eq!(
        resolves(&pool, operator, group).await,
        (false, false),
        "a revoked human no longer reads or writes the group"
    );
    assert_eq!(
        resolves(&pool, agent, group).await,
        (false, false),
        "nor does its agent"
    );
    assert!(
        resolves(&pool, operator, personal).await.0,
        "POSITIVE CONTROL: the lapse is scoped to verb-made groups"
    );
    assert_eq!(
        resolves(&pool, owner, group).await,
        (true, true),
        "the registered admin is unaffected"
    );
    let r = add(&pool, group, later, "reader").await;
    assert_eq!(code_of(&r).as_deref(), Some(NOT_BOUND), "{r:?}");
    let r = set_role(&pool, group, operator, "admin").await;
    assert_eq!(code_of(&r).as_deref(), Some(NOT_BOUND), "{r:?}");
}

/// A PROMOTION meets the operator-scope rule again: an operated agent added as
/// a reader while its operator wrote the group cannot be promoted once the
/// operator only reads it (a state the verbs never produce, set here out of
/// band), and can once the operator writes again.
#[sqlx::test(migrations = "../../migrations")]
async fn a_promotion_meets_the_operator_scope_again(pool: PgPool) {
    let owner = human(&pool, "promote-owner").await;
    let operator = human(&pool, "promote-operator").await;
    let agent = operated(&pool, operator, "promote-agent").await;
    let group = create(&pool, "Synthetic Promotion Team", owner)
        .await
        .expect("create");
    add(&pool, group, operator, "writer")
        .await
        .expect("operator");
    add(&pool, group, agent, "reader").await.expect("agent");
    sqlx::query(
        "UPDATE group_memberships SET role = 'reader' \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(operator)
    .execute(&pool)
    .await
    .expect("narrow the operator out of band");

    let r = set_role(&pool, group, agent, "writer").await;
    assert_eq!(code_of(&r).as_deref(), Some(OPERATOR_SCOPE), "{r:?}");
    assert_eq!(
        live_role(&pool, group, agent).await.as_deref(),
        Some("reader")
    );

    set_role(&pool, group, operator, "writer")
        .await
        .expect("the operator writes again");
    set_role(&pool, group, agent, "writer")
        .await
        .expect("POSITIVE CONTROL: promoted where its operator writes");
}

/// "Another admin" means another LIVE REGISTERED HUMAN admin. With a second
/// admin whose human client is suspended (so it is no longer a registered
/// human operator, and its viewer no longer carries the group), the first
/// admin is still the last one that counts: neither removable nor demotable.
/// Once the second admin's client is active again, the first is removable.
#[sqlx::test(migrations = "../../migrations")]
async fn only_a_live_human_admin_counts_as_another_admin(pool: PgPool) {
    let first = human(&pool, "counted-first").await;
    let second = human(&pool, "counted-second").await;
    let group = create(&pool, "Synthetic Counted Team", first)
        .await
        .expect("create");
    add(&pool, group, second, "admin")
        .await
        .expect("second admin");
    let set_client = |status: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "UPDATE oauth_clients SET status = $2 \
                  WHERE agent_id = $1 AND client_type = 'human'",
            )
            .bind(second)
            .bind(status)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("second admin's client -> {status}: {e}"));
        }
    };
    set_client("suspended").await;

    let r = remove(&pool, group, first).await;
    assert_eq!(code_of(&r).as_deref(), Some(LAST_ADMIN), "remove: {r:?}");
    let r = set_role(&pool, group, first, "writer").await;
    assert_eq!(code_of(&r).as_deref(), Some(LAST_ADMIN), "demote: {r:?}");
    assert_eq!(
        live_role(&pool, group, first).await.as_deref(),
        Some("admin")
    );

    // POSITIVE CONTROL: the second admin is a registered human again.
    set_client("active").await;
    let ok = remove(&pool, group, first)
        .await
        .expect("removable beside a live human admin");
    assert!(ok.applied, "{ok:?}");
}

/// Wait (bounded) until another backend running `fragment` is waiting on a
/// lock, or `task` has already finished. True when a waiter was seen.
async fn waits_on_a_lock(
    pool: &PgPool,
    fragment: &str,
    task: &tokio::task::JoinHandle<Result<(), sqlx::Error>>,
) -> bool {
    for _ in 0..400 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
              WHERE datname = current_database() AND pid <> pg_backend_pid() \
                AND wait_event_type = 'Lock' AND query LIKE '%' || $1 || '%'",
        )
        .bind(fragment)
        .fetch_one(pool)
        .await
        .expect("pg_stat_activity");
        if waiting > 0 {
            return true;
        }
        if task.is_finished() {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    false
}

/// Two concurrent removals of a group's two admins cannot both pass the
/// last-admin rule. The first removal holds its transaction open; the second
/// waits on the group row the first locked, and once the first commits, the
/// second sees one admin left and is refused with GRP02. The group keeps an
/// admin. (The test asserts the OUTCOME, not a timeout: the second removal
/// also meets the link lock later on, so a lock wait alone would not show that
/// the row lock is what serialises the decision.)
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_removals_of_two_admins_cannot_both_pass(pool: PgPool) {
    let first = human(&pool, "race-first").await;
    let second = human(&pool, "race-second").await;
    let group = create(&pool, "Synthetic Race Team", first)
        .await
        .expect("create");
    add(&pool, group, second, "admin")
        .await
        .expect("second admin");

    let mut c1 = maint(&pool).await;
    sqlx::query("BEGIN").execute(&mut *c1).await.expect("begin");
    sqlx::query("SELECT * FROM public.epigraph_team_group_remove_member($1, $2, $3)")
        .bind(group)
        .bind(first)
        .bind("race one")
        .execute(&mut *c1)
        .await
        .expect("the first removal passes, uncommitted");

    let racer = {
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut c2 = maint(&pool).await;
            let r = sqlx::query(
                "SELECT * FROM public.epigraph_team_group_remove_member($1, $2, 'race two')",
            )
            .bind(group)
            .bind(second)
            .execute(&mut *c2)
            .await
            .map(|_| ());
            reset(c2).await;
            r
        })
    };
    let waited = waits_on_a_lock(&pool, "race two", &racer).await;
    sqlx::query("COMMIT")
        .execute(&mut *c1)
        .await
        .expect("commit");
    reset(c1).await;
    let second_outcome = racer.await.expect("join");

    assert!(
        waited,
        "the second removal waited for the first: {second_outcome:?}"
    );
    assert_eq!(
        code_of(&second_outcome).as_deref(),
        Some(LAST_ADMIN),
        "the second removal, decided after the first committed: {second_outcome:?}"
    );
    assert_eq!(live_role(&pool, group, first).await, None);
    assert_eq!(
        live_role(&pool, group, second).await.as_deref(),
        Some("admin"),
        "the group keeps an admin"
    );
}

/// Two concurrent creations of the same name cannot both pass GRP06: the
/// second waits on the first's name lock and, once the first commits, is
/// refused. Exactly one group holds the name.
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_creations_of_one_name_cannot_both_pass(pool: PgPool) {
    let admin = human(&pool, "race-creator").await;
    let name = "Synthetic Racing Name";

    let mut c1 = maint(&pool).await;
    sqlx::query("BEGIN").execute(&mut *c1).await.expect("begin");
    sqlx::query("SELECT public.epigraph_create_team_group($1, $2, 'race one')")
        .bind(name)
        .bind(admin)
        .execute(&mut *c1)
        .await
        .expect("the first creation passes, uncommitted");

    let racer = {
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut c2 = maint(&pool).await;
            let r = sqlx::query("SELECT public.epigraph_create_team_group($1, $2, 'race two')")
                .bind(name)
                .bind(admin)
                .execute(&mut *c2)
                .await
                .map(|_| ());
            reset(c2).await;
            r
        })
    };
    let waited = waits_on_a_lock(&pool, "race two", &racer).await;
    sqlx::query("COMMIT")
        .execute(&mut *c1)
        .await
        .expect("commit");
    reset(c1).await;
    let second_outcome = racer.await.expect("join");

    assert!(
        waited,
        "the second creation waited for the first: {second_outcome:?}"
    );
    assert_eq!(
        code_of(&second_outcome).as_deref(),
        Some(DUPLICATE_NAME),
        "{second_outcome:?}"
    );
    let named: i64 =
        sqlx::query_scalar("SELECT count(*) FROM groups WHERE kind = 'team' AND display_name = $1")
            .bind(name)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(named, 1, "one group holds the name");
}

/// A verb in flight does not block ordinary writes that merely NAME the group:
/// while an uncommitted `add` holds the group row, a claim owned by the group
/// is inserted (its foreign key takes a KEY SHARE lock on the same row). The
/// verbs lock the row `FOR NO KEY UPDATE`, which still serialises them against
/// each other (the two tests above) but not against foreign-key readers.
#[sqlx::test(migrations = "../../migrations")]
async fn a_verb_in_flight_does_not_block_a_write_that_names_the_group(pool: PgPool) {
    let admin = human(&pool, "inflight-admin").await;
    let member = human(&pool, "inflight-member").await;
    let group = create(&pool, "Synthetic In-flight Team", admin)
        .await
        .expect("create");

    let mut c1 = maint(&pool).await;
    sqlx::query("BEGIN").execute(&mut *c1).await.expect("begin");
    sqlx::query("SELECT * FROM public.epigraph_team_group_add_member($1, $2, 'reader', 'held')")
        .bind(group)
        .bind(member)
        .execute(&mut *c1)
        .await
        .expect("an add holds the group row, uncommitted");

    let mut c2 = pool.acquire().await.expect("acquire");
    sqlx::query("SET lock_timeout = '2s'")
        .execute(&mut *c2)
        .await
        .expect("lock timeout");
    let write = sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES (gen_random_uuid(), 'in-flight probe', \
                 decode(md5('in-flight probe') || md5('in-flight probe'), 'hex'), 0.8, $1, \
                 true, 'group', $2)",
    )
    .bind(admin)
    .bind(group)
    .execute(&mut *c2)
    .await;
    sqlx::query("RESET lock_timeout")
        .execute(&mut *c2)
        .await
        .expect("reset lock timeout");
    sqlx::query("COMMIT")
        .execute(&mut *c1)
        .await
        .expect("commit");
    reset(c1).await;

    assert!(
        write.is_ok(),
        "a claim naming the group is not blocked by a verb in flight: {write:?}"
    );
    assert_eq!(
        live_role(&pool, group, member).await.as_deref(),
        Some("reader"),
        "and the verb committed"
    );
}

/// The in-body gate, on its own: with EXECUTE granted to the application role
/// (a later migration that grants too widely, simulated inside a transaction
/// that is rolled back), every verb still refuses a forged application session
/// with 42501, and the refusal is the body's own ("only a maintenance
/// session"), not the ACL's. The ACL refusal is pinned separately, by its own
/// message, in the forged-session test above.
#[sqlx::test(migrations = "../../migrations")]
async fn the_body_refuses_a_non_maintenance_session_even_with_execute(pool: PgPool) {
    let admin = human(&pool, "body-admin").await;
    let other = human(&pool, "body-other").await;
    let group = create(&pool, "Synthetic Body Team", admin)
        .await
        .expect("create");
    let audit_before = group_audit_count(&pool).await;
    let calls: [(&str, &str, &str); 4] = [
        (
            "create",
            "public.epigraph_create_team_group(text, uuid, text)",
            "SELECT public.epigraph_create_team_group('body probe ' || $1::text, $2, 'forged ' || $3::text)",
        ),
        (
            "add",
            "public.epigraph_team_group_add_member(uuid, uuid, text, text)",
            "SELECT * FROM public.epigraph_team_group_add_member($1, $2, 'writer', 'forged ' || $3::text)",
        ),
        (
            "set-role",
            "public.epigraph_team_group_set_member_role(uuid, uuid, text, text)",
            "SELECT * FROM public.epigraph_team_group_set_member_role($1, $3, 'reader', 'forged ' || $2::text)",
        ),
        (
            "remove",
            "public.epigraph_team_group_remove_member(uuid, uuid, text)",
            "SELECT * FROM public.epigraph_team_group_remove_member($1, $3, 'forged ' || $2::text)",
        ),
    ];
    for (what, signature, call) in calls {
        let mut tx = pool.begin().await.expect("begin");
        sqlx::query(&format!(
            "GRANT EXECUTE ON FUNCTION {signature} TO epigraph_app"
        ))
        .execute(&mut *tx)
        .await
        .expect("grant too widely, inside the transaction");
        sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_app")
            .execute(&mut *tx)
            .await
            .expect("downgrade to the application role");
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, true), \
                    set_config('epigraph.group_ids', $2, true), \
                    set_config('epigraph.writable_group_ids', $2, true)",
        )
        .bind(admin.to_string())
        .bind(group.to_string())
        .execute(&mut *tx)
        .await
        .expect("forge the session settings");
        let r = sqlx::query(call)
            .bind(group)
            .bind(other)
            .bind(admin)
            .execute(&mut *tx)
            .await;
        tx.rollback().await.expect("rollback");
        assert_eq!(
            code_of(&r).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "{what}: {r:?}"
        );
        assert!(
            message_of(&r).contains("only a maintenance session"),
            "{what}: refused by the body's own gate, not the ACL: {r:?}"
        );
    }
    assert_eq!(group_audit_count(&pool).await, audit_before, "no audit row");
    assert_eq!(live_role(&pool, group, other).await, None);
    assert_eq!(
        live_role(&pool, group, admin).await.as_deref(),
        Some("admin")
    );
}
